package config

import (
	"context"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const watchDebounce = 200 * time.Millisecond

// Watch calls onChange after path settles following a write. It watches the
// directory, because editors and Kubernetes replace the file instead of writing
// into it, which would orphan a watch on the file itself.
func Watch(ctx context.Context, path string, onChange func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(filepath.Dir(path)); err != nil {
		w.Close()
		return err
	}
	name := filepath.Clean(path)
	go func() {
		defer w.Close()
		var timer <-chan time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-w.Events:
				if filepath.Clean(ev.Name) == name && !ev.Has(fsnotify.Chmod) {
					timer = time.After(watchDebounce)
				}
			case <-w.Errors:
			case <-timer:
				timer = nil
				onChange()
			}
		}
	}()
	return nil
}
