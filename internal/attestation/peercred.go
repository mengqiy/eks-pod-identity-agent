package attestation

// This file covers the first link in the attestation chain: turning an accepted
// Unix socket connection into the kernel-attested identity of the process on the
// other end, and guarding that identity against PID reuse for the lifetime of
// the resolution.
//
// The property the whole design rests on is that SO_PEERCRED reports the
// credentials the kernel captured when the peer called connect(2). The caller
// cannot set or forge them. Everything downstream trusts this, so the ordering
// here is the substance of the defence, not incidental: the /proc handle is
// opened before anything else touches the PID, and it is rechecked after the pod
// has been resolved. See T3 for why.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// procRoot is the /proc mount the peer resolver reads. It is a package variable
// rather than the literal so a test can point the reader at a fixture tree,
// though the peer-credential tests use the real /proc with the test process as
// its own peer.
var procRoot = "/proc"

// Sentinel errors classifying why a peer could not be established. The attestor
// maps each onto a metric reason with errors.Is; they are not returned to the
// caller directly (the attestor wraps ErrUnattestable), so they carry no metric
// label of their own.
var (
	// errNotUnixSocket means the connection was not a *net.UnixConn, so
	// SO_PEERCRED cannot be read. A caller reaching the handler over TCP lands
	// here.
	errNotUnixSocket = errors.New("connection is not a unix socket")
	// errPeerCredFailed means the SO_PEERCRED read on the connection failed for
	// a reason other than the peer being gone.
	errPeerCredFailed = errors.New("reading peer credentials failed")
	// errPeerPIDZero means SO_PEERCRED reported PID 0, which happens when the
	// peer is in a different PID namespace than the agent. It means the agent is
	// running without hostPID and is a deployment bug, not a caller error.
	errPeerPIDZero = errors.New("SO_PEERCRED reported pid 0")
	// errPeerGone means the peer process could not be pinned under /proc because
	// it had already exited.
	errPeerGone = errors.New("peer process is gone")
	// errLivenessRecheckFailed means the peer handle failed the recheck after
	// pod resolution, so the resolved identity can no longer be trusted.
	errLivenessRecheckFailed = errors.New("peer liveness recheck failed")
)

// peerConn is the seam between the attestor and the kernel-attested peer. It is
// an interface so the attestor can be unit-tested with a fake peer that records
// the order of recheck relative to pod resolution, while production uses the
// real peerHandle over a Unix socket.
type peerConn interface {
	// pid is the peer's process ID in the agent's PID namespace, captured by
	// the kernel at connect time.
	pid() int
	// recheck confirms the handle still refers to the same process it did when
	// it was opened. It must be called after pod resolution.
	recheck() error
	// close releases the /proc handle.
	close() error
}

// peerHandle is a live handle to the peer process. procDir is kept open for the
// whole resolution: it pins the original process's /proc directory, so a read
// through it fails once the process exits rather than silently resolving a
// different process that inherited the PID.
type peerHandle struct {
	procPID   int
	uid       uint32
	gid       uint32
	startTime uint64
	procDir   *os.File
}

// peerFromConn reads the peer credentials off conn and pins the peer process.
// The order is deliberate and is the PID-reuse defence: read SO_PEERCRED, refuse
// PID 0, then open the /proc handle before reading anything else about the PID,
// and record the process start time through that handle. A caller that has
// already exited is refused here rather than misattributed.
func peerFromConn(conn net.Conn) (peerConn, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errNotUnixSocket
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("%w: obtaining syscall conn: %v", errPeerCredFailed, err)
	}

	var ucred *unix.Ucred
	var credErr error
	// RawConn.Control is the only supported way to touch the fd without breaking
	// the runtime poller. The credentials are the kernel's record from connect
	// time, so they are stable for the life of the connection.
	if ctrlErr := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return nil, fmt.Errorf("%w: controlling raw conn: %v", errPeerCredFailed, ctrlErr)
	}
	if credErr != nil {
		return nil, fmt.Errorf("%w: getsockopt SO_PEERCRED: %v", errPeerCredFailed, credErr)
	}

	// PID 0 is its own path: it means the agent is deployed without hostPID and
	// sits in a sibling PID namespace, so the kernel has no number for the peer.
	if ucred.Pid == 0 {
		return nil, errPeerPIDZero
	}

	// Pin the process before reading anything else about the PID. This is the
	// narrowest possible reuse window.
	procDir, err := os.Open(filepath.Join(procRoot, strconv.Itoa(int(ucred.Pid))))
	if err != nil {
		return nil, fmt.Errorf("%w: opening /proc handle: %v", errPeerGone, err)
	}

	h := &peerHandle{
		procPID: int(ucred.Pid),
		uid:     ucred.Uid,
		gid:     ucred.Gid,
		procDir: procDir,
	}

	startTime, err := h.readStartTime()
	if err != nil {
		_ = h.close()
		return nil, fmt.Errorf("%w: reading start time: %v", errPeerGone, err)
	}
	h.startTime = startTime

	return h, nil
}

func (h *peerHandle) pid() int { return h.procPID }

// recheck confirms the pinned process is still the same one SO_PEERCRED
// reported. It reads three things through the retained handle rather than by
// path, so a PID that has been reused since the handle was opened is detected:
// the /proc directory still fstats (the process still exists), its owning UID
// and GID still match what the kernel reported, and its start time is unchanged.
// Any mismatch is a refusal.
func (h *peerHandle) recheck() error {
	var st unix.Stat_t
	if err := unix.Fstat(int(h.procDir.Fd()), &st); err != nil {
		return fmt.Errorf("%w: fstat /proc handle: %v", errLivenessRecheckFailed, err)
	}
	if st.Uid != h.uid || st.Gid != h.gid {
		return fmt.Errorf("%w: owner changed, was uid=%d gid=%d now uid=%d gid=%d",
			errLivenessRecheckFailed, h.uid, h.gid, st.Uid, st.Gid)
	}

	startTime, err := h.readStartTime()
	if err != nil {
		return fmt.Errorf("%w: re-reading start time: %v", errLivenessRecheckFailed, err)
	}
	if startTime != h.startTime {
		return fmt.Errorf("%w: start time changed, was %d now %d",
			errLivenessRecheckFailed, h.startTime, startTime)
	}
	return nil
}

func (h *peerHandle) close() error {
	return h.procDir.Close()
}

// readStartTime reads field 22 (starttime) of /proc/<pid>/stat through the
// retained directory handle. Reading through the handle rather than by path is
// what makes this safe against PID reuse: the openat resolves relative to the
// pinned directory, so it reads the original process's stat or fails, never a
// different process that took the same number.
func (h *peerHandle) readStartTime() (uint64, error) {
	fd, err := unix.Openat(int(h.procDir.Fd()), "stat", unix.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(fd), "stat")
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}
	return parseStartTime(string(data))
}

// parseStartTime extracts field 22 (starttime, in clock ticks since boot) from a
// /proc/<pid>/stat line. The process's comm (field 2) is wrapped in parentheses
// and can itself contain spaces and parentheses, so the fields after it are
// located from the last ')' rather than by splitting the whole line. After that
// point field 3 (state) is the first token, so starttime is the 20th token.
func parseStartTime(stat string) (uint64, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 || end+1 >= len(stat) {
		return 0, fmt.Errorf("malformed stat line: no comm field")
	}
	fields := strings.Fields(stat[end+1:])
	// fields[0] is state (field 3); starttime is field 22, i.e. index 22-3 = 19.
	const starttimeIndex = 19
	if len(fields) <= starttimeIndex {
		return 0, fmt.Errorf("malformed stat line: only %d fields after comm", len(fields))
	}
	startTime, err := strconv.ParseUint(fields[starttimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing starttime %q: %w", fields[starttimeIndex], err)
	}
	return startTime, nil
}
