package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

var errCapacity = errors.New("storage capacity unavailable")
var errStorageBusy = errors.New("storage busy")

type eventStorage struct {
	root   *os.Root
	lock   *os.File
	mu     sync.Mutex
	limits limits
	// Injectable for deterministic low-space tests; real checks use the open fd.
	freeSpace func() (bytes, inodes uint64, hasInodes bool, err error)
}

func openStorage(directory string, l limits) (*eventStorage, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			root.Close()
		}
	}()
	// Validate the directory we actually opened, then anchor all operations to it.
	info, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("events directory must be owned by this user and not group/world writable")
	}
	lock, err := root.OpenFile(".hec.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !success {
			lock.Close()
		}
	}()
	info, err = lock.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("unsafe events lock file")
	}
	// Use the same lock as Python; do not remove it while either server is running.
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("events directory already in use: %w", err)
	}
	s := &eventStorage{root: root, lock: lock, limits: l}
	s.freeSpace = func() (uint64, uint64, bool, error) {
		var fs syscall.Statfs_t
		if err := syscall.Fstatfs(int(lock.Fd()), &fs); err != nil {
			return 0, 0, false, err
		}
		block := uint64(fs.Bsize)
		available := uint64(fs.Bavail)
		free := ^uint64(0)
		if block == 0 {
			return 0, 0, false, errors.New("invalid filesystem block size")
		}
		if available <= free/block {
			free = available * block
		}
		return free, uint64(fs.Ffree), fs.Files > 0, nil
	}
	// Writability is distinct from configured quotas. Exceeding a quota need not
	// prevent startup, but a filesystem that cannot create a probe will do so.
	f, name, err := s.temporary()
	if err != nil {
		return nil, err
	}
	closeErr := f.Close()
	removeErr := root.Remove(name)
	if closeErr != nil {
		return nil, closeErr
	}
	if removeErr != nil {
		return nil, removeErr
	}
	success = true
	return s, nil
}

func (s *eventStorage) Close() error {
	// Closing releases flock. Keep .hec.lock in place to avoid split locks.
	return errors.Join(s.root.Close(), s.lock.Close())
}

func (s *eventStorage) temporary() (*os.File, string, error) {
	name := ".pending-" + rand.Text()
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	return f, name, err
}

// Called with mu held. Include existing and orphan files, and stop scanning as
// soon as a quota is exceeded. No unbounded directory-list allocation.
func (s *eventStorage) capacity(size int64) error {
	if size < 0 || size > s.limits.maxStorageBytes {
		return errCapacity
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	var total int64
	count := 0
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			if entry.Name() == ".hec.lock" {
				continue
			}
			count++
			if count >= s.limits.maxFiles {
				return errCapacity
			} // Reserve one pending file.
			info, err := entry.Info()
			if errors.Is(err, os.ErrNotExist) {
				continue
			} // Concurrent operator retention.
			if err != nil {
				return err
			}
			n := info.Size()
			if n < 0 || n > s.limits.maxStorageBytes-size-total {
				return errCapacity
			}
			total += n
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	free, inodes, hasInodes, err := s.freeSpace()
	if err != nil {
		return err
	}
	reserve := uint64(s.limits.minFreeBytes)
	if free < reserve || uint64(size) > free-reserve {
		return errCapacity
	}
	if hasInodes && (inodes == 0 || inodes-1 < uint64(s.limits.minFreeInodes)) {
		return errCapacity
	}
	return nil
}

func (s *eventStorage) ready() error {
	if !s.mu.TryLock() {
		return errStorageBusy
	}
	defer s.mu.Unlock()
	if err := s.capacity(1); err != nil {
		return err
	}
	f, name, err := s.temporary()
	if err != nil {
		return err
	}
	return errors.Join(f.Close(), s.root.Remove(name))
}

// Validation is complete before storage admission. The size is the exact compact
// array length; writes are incremental, with no second full-batch encoding.
func (s *eventStorage) store(ctx context.Context, events []json.RawMessage, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.capacity(size); err != nil {
		return err
	}
	f, name, err := s.temporary()
	if err != nil {
		return err
	}
	defer s.root.Remove(name)
	defer f.Close()
	if _, err := io.WriteString(f, "["); err != nil {
		return err
	}
	for i, event := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i > 0 {
			if _, err := io.WriteString(f, ","); err != nil {
				return err
			}
		}
		if _, err := f.Write(event); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(f, "]\n"); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Hard-link publication never replaces a preexisting event file.
	return s.root.Link(name, "events-"+name[len(".pending-"):]+".json")
}

func storagePressure(err error) bool {
	return errors.Is(err, errCapacity) || errors.Is(err, errStorageBusy) || errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
