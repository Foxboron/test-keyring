package main

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	session      *Keyring = &Keyring{ringid: unix.KEY_SPEC_SESSION_KEYRING}
	once         sync.Once
	agentKeyring *Keyring
)

type KeyPerm uint32

const (
	// PermOtherAll sets all permission for Other
	PermOtherAll KeyPerm = 0x3f << (8 * iota)
	// PermGroupAll sets all permission for Group
	PermGroupAll
	// PermUserAll sets all permission for User
	PermUserAll
	// PermProcessAll sets all permission for Processor
	PermProcessAll
)

const (
	KEYCTL_PERM_VIEW    = uint32(1 << 0)
	KEYCTL_PERM_READ    = uint32(1 << 1)
	KEYCTL_PERM_WRITE   = uint32(1 << 2)
	KEYCTL_PERM_SEARCH  = uint32(1 << 3)
	KEYCTL_PERM_LINK    = uint32(1 << 4)
	KEYCTL_PERM_SETATTR = uint32(1 << 5)
	KEYCTL_PERM_ALL     = uint32((1 << 6) - 1)

	KEYCTL_PERM_OTHERS  = 0
	KEYCTL_PERM_GROUP   = 8
	KEYCTL_PERM_USER    = 16
	KEYCTL_PERM_PROCESS = 24
)

func SetPerm(k int, p uint32) error {
	err := unix.KeyctlSetperm(k, uint32(p))
	return err
}

func goid() int {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	id, err := strconv.Atoi(idField)
	if err != nil {
		panic(fmt.Sprintf("cannot get goroutine id: %v", err))
	}
	return id
}

type ThreadKeyring struct {
	rw        sync.RWMutex
	wg        sync.WaitGroup
	addkey    chan *addkeyMsg
	removekey chan *removekeyMsg
	readkey   chan *readkeyMsg
}

type addkeyMsg struct {
	name string
	key  []byte
	cb   chan error
}

type removekeyMsg struct {
	name string
	cb   chan error
}

type readkeyRet struct {
	key []byte
	err error
}

type readkeyMsg struct {
	name string
	cb   chan *readkeyRet
}

func GetKeyring(ctx context.Context) (*ThreadKeyring, error) {
	var tk ThreadKeyring
	var err error

	tk.addkey = make(chan *addkeyMsg)
	tk.removekey = make(chan *removekeyMsg)
	tk.readkey = make(chan *readkeyMsg)

	tk.wg.Add(1)
	go func() {
		var ak *Keyring
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ak, err = session.CreateKeyring()
		if err != nil {
			return
		}
		for {
			select {
			case msg := <-tk.addkey:
				tk.rw.Lock()
				msg.cb <- ak.AddKey(msg.name, msg.key)
				tk.rw.Unlock()
			case msg := <-tk.readkey:
				tk.rw.Lock()
				key, err := ak.ReadKey(msg.name)
				msg.cb <- &readkeyRet{key, err}
				tk.rw.Unlock()
			case msg := <-tk.removekey:
				tk.rw.Lock()
				msg.cb <- ak.RemoveKey(msg.name)
				tk.rw.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
	return &tk, err
}

func (tk *ThreadKeyring) Wait() {
	tk.wg.Wait()
}

func (tk *ThreadKeyring) AddKey(name string, key []byte) error {
	cb := make(chan error)
	tk.addkey <- &addkeyMsg{name, key, cb}
	return <-cb
}

func (tk *ThreadKeyring) RemoveKey(name string) error {
	cb := make(chan error)
	tk.removekey <- &removekeyMsg{name, cb}
	return <-cb
}

func (tk *ThreadKeyring) ReadKey(name string) ([]byte, error) {
	cb := make(chan *readkeyRet)
	tk.readkey <- &readkeyMsg{name, cb}
	ret := <-cb
	if ret.err != nil {
		return nil, ret.err
	}
	return ret.key, nil
}

type Keyring struct {
	ringid int
}

func (ring *Keyring) keyID() (int, error) {
	return unix.KeyctlGetKeyringID(ring.ringid, false)
}

func (ring *Keyring) CreateKeyring() (*Keyring, error) {
	id, err := unix.KeyctlJoinSessionKeyring("ssh-tpm-agent")
	if err != nil {
		return nil, err
	}
	return &Keyring{ringid: id}, nil
}

func (k *Keyring) AddKey(name string, b []byte) error {
	fmt.Println("addkey ", name, k.ringid, goid())
	_, err := unix.AddKey("user", name, b, k.ringid)
	if err != nil {
		return fmt.Errorf("failed add-key: %v", err)
	}
	return nil
}

func (k *Keyring) keyctlRead(id int) ([]byte, error) {
	var buffer []byte
	sz, err := unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), nil, 0)
	if err != nil {
		return nil, err
	}
	buffer = make([]byte, sz)
	if _, err = unix.KeyctlBuffer(unix.KEYCTL_READ, int(id), buffer, 0); err != nil {
		return nil, err
	}
	return buffer, nil
}

func (k *Keyring) ReadKey(name string) ([]byte, error) {
	fmt.Println("readkey ", k.ringid, goid())
	id, err := unix.RequestKey("user", name, "", k.ringid)
	if err != nil {
		return nil, err
	}
	return k.keyctlRead(id)
}

func (k *Keyring) RemoveKey(name string) error {
	id, err := unix.RequestKey("user", name, "", k.ringid)
	if err != nil {
		return fmt.Errorf("failed remove-key: %v", err)
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, k.ringid, 0, 0)
	return err
}

func (k *Keyring) Describe() error {
	description, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, k.ringid)
	if err != nil {
		return err
	}
	fields := strings.Split(description, ";")
	if len(fields) < 1 {
		return fmt.Errorf("no data")
	}

	data := make(map[string]string)
	names := []string{"type", "uid", "gid", "perm"} // according to keyctl_describe(3) new fields are added at the end
	data["description"] = fields[len(fields)-1]     // according to keyctl_describe(3) description is always last
	for i, f := range fields[:len(fields)-1] {
		if i >= len(names) {
			// Do not stumble upon unknown fields
			break
		}
		data[names[i]] = f
	}

	fmt.Println(data)
	return nil
}
