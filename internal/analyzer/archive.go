package analyzer

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/nwaples/rardecode/v2"
)

const (
	maxMemberBytes = 64 << 20
	maxTotalBytes  = 256 << 20
	maxDepth       = 3
)

// Member is one file from an attachment; Data is empty when it could not be read (see Note).
type Member struct {
	Path string
	Data []byte
	Note string
}

type budget struct{ left int64 }

func (b *budget) take(size int64) bool {
	if size > maxMemberBytes || size > b.left {
		return false
	}
	b.left -= size
	return true
}

// Unpack flattens archives (recursively) into their files; anything else comes back as one member.
// Archives are read in memory, nothing is written to disk.
func Unpack(name string, data []byte) []Member {
	return unpack(name, data, 0, &budget{maxTotalBytes})
}

func unpack(name string, data []byte, depth int, b *budget) []Member {
	kind := Sniff(data, name)
	if (kind != "zip" && kind != "rar" && kind != "7z") || depth >= maxDepth {
		return []Member{{Path: name, Data: data}}
	}
	out := []Member{{Path: name, Note: kind + " archive"}}
	entries, err := listArchive(kind, data, b)
	for _, e := range entries {
		full := name + "/" + e.Path
		if e.Data == nil {
			out = append(out, Member{Path: full, Note: e.Note})
			continue
		}
		out = append(out, unpack(full, e.Data, depth+1, b)...)
	}
	if err != nil {
		out = append(out, Member{Path: name, Note: fmt.Sprintf("cannot open %s: %v", kind, err)})
	}
	return out
}

const encryptedNote = "password-protected (cannot be analysed)"

func tooLarge(size int64) string {
	return fmt.Sprintf("skipped: too large (%d bytes, possible zip bomb)", size)
}

func listArchive(kind string, data []byte, b *budget) ([]Member, error) {
	switch kind {
	case "zip":
		return listZip(data, b)
	case "7z":
		return list7z(data, b)
	default:
		return listRar(data, b)
	}
}

func listZip(data []byte, b *budget) ([]Member, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	var out []Member
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		size := int64(f.UncompressedSize64)
		switch {
		case f.Flags&1 != 0:
			out = append(out, Member{Path: f.Name, Note: encryptedNote})
		case !b.take(size):
			out = append(out, Member{Path: f.Name, Note: tooLarge(size)})
		default:
			body, err := readAll(f.Open)
			if err != nil {
				out = append(out, Member{Path: f.Name, Note: "cannot read: " + err.Error()})
				continue
			}
			out = append(out, Member{Path: f.Name, Data: body})
		}
	}
	return out, nil
}

func list7z(data []byte, b *budget) ([]Member, error) {
	zr, err := sevenzip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if isPasswordError(err) {
			return []Member{{Path: "*", Note: encryptedNote}}, nil
		}
		return nil, err
	}
	var out []Member
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		size := int64(f.UncompressedSize)
		if !b.take(size) {
			out = append(out, Member{Path: f.Name, Note: tooLarge(size)})
			continue
		}
		body, err := readAll(f.Open)
		switch {
		case err != nil && isPasswordError(err):
			out = append(out, Member{Path: f.Name, Note: encryptedNote})
		case err != nil:
			out = append(out, Member{Path: f.Name, Note: "cannot read: " + err.Error()})
		default:
			out = append(out, Member{Path: f.Name, Data: body})
		}
	}
	return out, nil
}

func listRar(data []byte, b *budget) ([]Member, error) {
	rr, err := rardecode.NewReader(bytes.NewReader(data))
	if err != nil {
		if errors.Is(err, rardecode.ErrArchiveEncrypted) {
			return []Member{{Path: "*", Note: encryptedNote}}, nil
		}
		return nil, err
	}
	var out []Member
	for {
		h, err := rr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if errors.Is(err, rardecode.ErrArchiveEncrypted) || errors.Is(err, rardecode.ErrArchivedFileEncrypted) {
			return append(out, Member{Path: "*", Note: encryptedNote}), nil
		}
		if err != nil {
			return out, err
		}
		if h.IsDir {
			continue
		}
		if h.Encrypted {
			out = append(out, Member{Path: h.Name, Note: encryptedNote})
			continue
		}
		if !b.take(h.UnPackedSize) {
			out = append(out, Member{Path: h.Name, Note: tooLarge(h.UnPackedSize)})
			continue
		}
		body, err := io.ReadAll(io.LimitReader(rr, maxMemberBytes+1))
		if err != nil {
			out = append(out, Member{Path: h.Name, Note: "cannot read: " + err.Error()})
			continue
		}
		out = append(out, Member{Path: h.Name, Data: body})
	}
}

func isPasswordError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "password") || strings.Contains(msg, "encrypt")
}

// readAll caps every read so a lying size header cannot exhaust memory.
func readAll(open func() (io.ReadCloser, error)) ([]byte, error) {
	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, maxMemberBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMemberBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxMemberBytes)
	}
	return body, nil
}
