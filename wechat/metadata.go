package wechat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	encryptedHeaderSize               = 6
	encryptedBlockSize                = 1024
	encryptedLogicalPrefixSize        = encryptedBlockSize - 1
	encryptedRawOffsetDelta           = encryptedHeaderSize + 1
	maxMetadataEntrySize       uint32 = 2 * 1024 * 1024
	maxCodeMetadataSize        uint32 = 1 * 1024 * 1024
	maxAppNameLength                  = 128
)

const (
	appNameSourceLocalMetadata   = "local-metadata"
	appNameSourcePackageConfig   = "package-config"
	appNameSourceWxShare         = "wx-share"
	appNameSourceShareCard       = "share-card"
	appNameSourcePosterBrand     = "poster-brand"
	appNameSourceNavigationTitle = "navigation-title"
	appNameSourceCodeCandidate   = "code-candidate"
)

var (
	appConfigNameFields = []string{
		"appName",
		"miniProgramName",
		"nickname",
		"brandName",
		"storeName",
		"mallName",
		"name",
		"title",
	}
	localNameFields = []string{
		"appName",
		"miniProgramName",
		"nickname",
		"brandName",
		"storeName",
		"mallName",
		"name",
		"title",
	}
	codeNamePatterns = []*regexp.Regexp{
		regexp.MustCompile("(?is)[\"']?appId[\"']?\\s*[:=]\\s*[\"'][^\"']{4,64}[\"']\\s*,\\s*[\"']?appName[\"']?\\s*[:=]\\s*[\"']([^\"'\\r\\n]{1,128})[\"']\\s*,\\s*[\"']?appVersion[\"']?"),
		regexp.MustCompile("(?is)[\"']?appName[\"']?\\s*[:=]\\s*[\"']([^\"'\\r\\n]{1,128})[\"']\\s*,\\s*[\"']?appVersion[\"']?\\s*[:=]\\s*[\"'][^\"']{1,64}[\"']\\s*,\\s*[\"']?appVersionCode[\"']?\\s*[:=]"),
		regexp.MustCompile("(?is)authFloatInfo\\s*[:=]\\s*\\{[^}]{0,1000}\\bname\\s*[:=]\\s*[\"']([^\"'\\r\\n]{1,128})[\"']"),
		regexp.MustCompile("(?m)\\bAPPNAME\\s*[:=]\\s*[\"']([^\"'\\r\\n]{1,128})[\"']"),
		// Bundle-level navigation title, which is the only identity hint most
		// modern compiled mini programs keep in their code.
		regexp.MustCompile("(?is)[\"']?navigationBarTitleText[\"']?\\s*[:=]\\s*[\"']([^\"'\\r\\n]{1,128})[\"']"),
	}
	// shareTitlePattern matches the return value of a WeChat share callback:
	// `return { title: "...", path: "/pages/index/index" }`. The share card
	// title is what users see for the mini program, so it is the most reliable
	// name hint available in compiled code.
	shareTitlePattern = regexp.MustCompile("(?is)\\btitle\\s*:\\s*[\"']([^\"'\\r\\n]{1,128})[\"']\\s*,\\s*path\\s*:\\s*[\"']([^\"'\\r\\n]{1,256})[\"']")
	// shareHomePathPattern identifies the share callback that points at the
	// program home page, whose title is the program name rather than a
	// promotional label for one sub page.
	shareHomePathPattern = regexp.MustCompile(`(?i)^/?(pages/(index|home|main|entry|app)(/|\.html$))`)
	// posterBrandPattern matches the brand label printed in a share poster's
	// logo area, e.g. `C(_,{text:"建发房产钻石会",top:...})`. Shared posters
	// always carry the program's own brand, while page titles often name a
	// functional module such as a cashier or a coupon page.
	posterBrandPattern = regexp.MustCompile("(?is)\\btext\\s*:\\s*[\"']([^\"'\\r\\n]{2,40})[\"']\\s*,\\s*(?:top|left|fontSize|lineHeight|color|bold)\\s*:")
	// wxSharePattern matches the project's own share helper wrapper:
	// `this.wxShare({title:"<name>"})`. It is the most reliable name source
	// because it is written explicitly by the developer as the program title.
	wxSharePattern       = regexp.MustCompile(`(?is)\bwxShare\s*\(\s*\{[^}]{0,400}?\btitle\s*:\s*["']([^"'\\r\\n]{2,60})["']`)
	codeNameFilePriority = map[string]int{
		"common/vendor.js": 0,
		"app-service.js":   1,
		"app.js":           2,
		"common/app.js":    3,
		"common/main.js":   4,
		"main.js":          5,
		"vendor.js":        6,
		"manifest.js":      7,
	}
	// gameNameFilePriority ranks the config files shipped by mini games, which
	// have no app-config.json and no page table.
	gameNameFilePriority = map[string]int{
		"project.json":     0,
		"game.json":        1,
		"game-config.json": 2,
	}
	// codeNamePriorityBase ranks every code scan below the structural sources
	// (package config and navigation titles), which use priorities 0..17.
	codeNamePriorityBase = 100
	// gameNamePriorityBase ranks mini game config below structural sources but
	// above raw code scanning, because it is parsed JSON rather than a guess.
	gameNamePriorityBase    = 20
	knownLocalMetadataFiles = []string{
		"appinfo.json",
		"app-info.json",
		"info.json",
		"adapter-config.json",
	}
	// initial-rendering-cache-config.json is not listed: in WeChat v4 it is a
	// placeholder whose content is only "{}".
)

type appNameResult struct {
	name   string
	source string
}

type wxapkgIndexEntry struct {
	name   string
	offset uint32
	size   uint32
}

// wxapkgDataReader exposes the logical, decrypted wxapkg bytes through
// ReaderAt without loading the package body into memory.
type wxapkgDataReader struct {
	file            *os.File
	logicalSize     int64
	decryptedPrefix []byte
	xorKey          byte
}

func (r *wxapkgDataReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative wxapkg read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.logicalSize {
		return 0, io.EOF
	}

	readLen := len(p)
	if remaining := r.logicalSize - off; int64(readLen) > remaining {
		readLen = int(remaining)
	}

	if len(r.decryptedPrefix) == 0 {
		n, err := r.file.ReadAt(p[:readLen], off)
		if n != readLen && err == nil {
			err = io.ErrUnexpectedEOF
		}
		if readLen != len(p) && err == nil {
			err = io.EOF
		}
		return n, err
	}

	read := 0
	for read < readLen {
		logicalOffset := off + int64(read)
		if logicalOffset < int64(len(r.decryptedPrefix)) {
			n := readLen - read
			if available := len(r.decryptedPrefix) - int(logicalOffset); n > available {
				n = available
			}
			copy(p[read:read+n], r.decryptedPrefix[int(logicalOffset):int(logicalOffset)+n])
			read += n
			continue
		}

		rawOffset := logicalOffset + encryptedRawOffsetDelta
		n := readLen - read
		nRead, err := r.file.ReadAt(p[read:read+n], rawOffset)
		for i := read; i < read+nRead; i++ {
			p[i] ^= r.xorKey
		}
		read += nRead
		if err != nil {
			return read, err
		}
		if nRead == 0 {
			return read, io.ErrUnexpectedEOF
		}
	}

	if readLen != len(p) {
		return read, io.EOF
	}
	return read, nil
}

func (r *wxapkgDataReader) Close() error {
	return r.file.Close()
}

func openWxapkgDataReader(path, wxid string) (*wxapkgDataReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	closeWithError := func(err error) (*wxapkgDataReader, error) {
		_ = file.Close()
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		return closeWithError(err)
	}
	if info.Size() < 14 {
		return closeWithError(errors.Errorf("wxapkg file is too short: %d bytes", info.Size()))
	}

	marker := make([]byte, 14)
	if _, err := io.ReadFull(file, marker); err != nil {
		return closeWithError(err)
	}
	if marker[0] == 0xBE && marker[13] == 0xED {
		return &wxapkgDataReader{file: file, logicalSize: info.Size()}, nil
	}

	if wxid == "" {
		return closeWithError(errors.New("encrypted wxapkg requires a wxid"))
	}
	minimumSize := int64(encryptedHeaderSize + encryptedBlockSize)
	if info.Size() < minimumSize {
		return closeWithError(errors.Errorf("encrypted wxapkg file is too short: %d bytes", info.Size()))
	}

	encryptedBlock := make([]byte, encryptedBlockSize)
	if _, err := file.ReadAt(encryptedBlock, encryptedHeaderSize); err != nil {
		return closeWithError(err)
	}

	key := pbkdf2.Key([]byte(wxid), []byte("saltiest"), 1000, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return closeWithError(err)
	}
	decryptedPrefix := make([]byte, encryptedBlockSize)
	cipher.NewCBCDecrypter(block, []byte("the iv: 16 bytes")).CryptBlocks(decryptedPrefix, encryptedBlock)

	xorKey := byte(0x66)
	if len(wxid) >= 2 {
		xorKey = wxid[len(wxid)-2]
	}
	return &wxapkgDataReader{
		file:            file,
		logicalSize:     info.Size() - encryptedRawOffsetDelta,
		decryptedPrefix: decryptedPrefix[:encryptedLogicalPrefixSize],
		xorKey:          xorKey,
	}, nil
}

func readAtFull(reader io.ReaderAt, data []byte, offset int64) error {
	if offset < 0 {
		return errors.New("negative wxapkg read offset")
	}
	n, err := reader.ReadAt(data, offset)
	if n != len(data) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func parseWxapkgIndex(reader io.ReaderAt, logicalSize int64) ([]wxapkgIndexEntry, error) {
	if logicalSize < 18 {
		return nil, errors.Errorf("wxapkg file is too short: %d bytes", logicalSize)
	}

	offset := int64(0)
	readByte := func() (byte, error) {
		var data [1]byte
		if err := readAtFull(reader, data[:], offset); err != nil {
			return 0, err
		}
		offset++
		return data[0], nil
	}
	readUint32 := func() (uint32, error) {
		var data [4]byte
		if err := readAtFull(reader, data[:], offset); err != nil {
			return 0, err
		}
		offset += 4
		return binary.BigEndian.Uint32(data[:]), nil
	}

	firstMark, err := readByte()
	if err != nil {
		return nil, errors.Errorf("read wxapkg first marker: %v", err)
	}
	if _, err := readUint32(); err != nil {
		return nil, errors.Errorf("read wxapkg header: %v", err)
	}
	if _, err := readUint32(); err != nil {
		return nil, errors.Errorf("read wxapkg index length: %v", err)
	}
	if _, err := readUint32(); err != nil {
		return nil, errors.Errorf("read wxapkg body length: %v", err)
	}
	lastMark, err := readByte()
	if err != nil {
		return nil, errors.Errorf("read wxapkg last marker: %v", err)
	}
	if firstMark != 0xBE || lastMark != 0xED {
		return nil, errors.New("invalid wxapkg markers")
	}

	fileCount, err := readUint32()
	if err != nil {
		return nil, errors.Errorf("read wxapkg file count: %v", err)
	}
	if fileCount > maxWxapkgFileCount {
		return nil, errors.Errorf("wxapkg file count %d exceeds limit %d", fileCount, maxWxapkgFileCount)
	}

	entries := make([]wxapkgIndexEntry, 0, int(fileCount))
	for i := uint32(0); i < fileCount; i++ {
		nameLen, err := readUint32()
		if err != nil {
			return nil, errors.Errorf("read wxapkg entry %d name length: %v", i, err)
		}
		if nameLen > maxWxapkgNameLength {
			return nil, errors.Errorf("wxapkg entry %d name length %d exceeds limit %d", i, nameLen, maxWxapkgNameLength)
		}
		if uint64(offset)+uint64(nameLen)+8 > uint64(logicalSize) {
			return nil, errors.Errorf("wxapkg entry %d index exceeds file boundary", i)
		}

		nameBytes := make([]byte, int(nameLen))
		if err := readAtFull(reader, nameBytes, offset); err != nil {
			return nil, errors.Errorf("read wxapkg entry %d name: %v", i, err)
		}
		offset += int64(nameLen)

		entryOffset, err := readUint32()
		if err != nil {
			return nil, errors.Errorf("read wxapkg entry %d offset: %v", i, err)
		}
		entrySize, err := readUint32()
		if err != nil {
			return nil, errors.Errorf("read wxapkg entry %d size: %v", i, err)
		}
		if entrySize > maxEntrySize {
			return nil, errors.Errorf("wxapkg entry %q size %d exceeds limit %d", string(nameBytes), entrySize, maxEntrySize)
		}
		if uint64(entryOffset)+uint64(entrySize) > uint64(logicalSize) {
			return nil, errors.Errorf("wxapkg entry %q exceeds file boundary", string(nameBytes))
		}

		name, err := normalizeArchiveEntryName(string(nameBytes))
		if err != nil {
			return nil, errors.Errorf("invalid wxapkg entry name %q: %v", string(nameBytes), err)
		}
		entries = append(entries, wxapkgIndexEntry{name: name, offset: entryOffset, size: entrySize})
	}
	return entries, nil
}

func readWxapkgAppName(path, wxid string) (string, error) {
	result, err := readWxapkgAppNameResult(path, wxid)
	return result.name, err
}

func readWxapkgAppNameResult(path, wxid string) (appNameResult, error) {
	reader, err := openWxapkgDataReader(path, wxid)
	if err != nil {
		return appNameResult{}, err
	}
	defer reader.Close()

	entries, err := parseWxapkgIndex(reader, reader.logicalSize)
	if err != nil {
		return appNameResult{}, err
	}

	var navigationResult appNameResult
	var wxShareResult appNameResult
	var shareResult appNameResult
	sharePriority := int(^uint(0) >> 1)
	var posterResult appNameResult
	posterPriority := int(^uint(0) >> 1)
	var gameResult appNameResult
	gamePriority := int(^uint(0) >> 1)
	var codeResult appNameResult
	codePriority := int(^uint(0) >> 1)
	for _, entry := range entries {
		if entry.name == "app-config.json" {
			if entry.size > maxMetadataEntrySize {
				continue
			}
			data, err := readWxapkgEntry(reader, entry, maxMetadataEntrySize)
			if err != nil {
				return appNameResult{}, err
			}
			result := appNameFromConfigResult(data)
			if result.source == appNameSourcePackageConfig {
				return result, nil
			}
			if result.source == appNameSourceNavigationTitle && navigationResult.name == "" {
				navigationResult = result
			}
			continue
		}

		if base, ok := gameNameFilePriority[entry.name]; ok {
			if priority := gameNamePriorityBase + base; priority < gamePriority && entry.size <= maxMetadataEntrySize {
				if data, err := readWxapkgEntry(reader, entry, maxMetadataEntrySize); err == nil {
					if result := appNameFromGameConfig(data); result.name != "" {
						gameResult = result
						gamePriority = priority
					}
				}
			}
			continue
		}

		priority, ok := codeEntryPriority(entry.name)
		if !ok || priority >= codePriority {
			continue
		}
		data, err := readWxapkgEntrySample(reader, entry, maxCodeMetadataSize)
		if err != nil {
			continue
		}
		if sharePriority > priority {
			if result := appNameFromWxShare(data, isHomeShareEntry(entry.name)); result.name != "" {
				// A home page wxShare title is the program title itself, so it
				// short-circuits every other source.
				if isHomeShareEntry(entry.name) {
					return result, nil
				}
				wxShareResult = result
			}
		}
		if sharePriority > priority {
			if result := appNameFromShareTitles(data); result.name != "" {
				shareResult = result
				sharePriority = priority
			}
		}
		if posterPriority > priority {
			if result := appNameFromPosterBrand(data); result.name != "" {
				posterResult = result
				posterPriority = priority
			}
		}
		result := appNameFromCodeContent(data)
		if result.name != "" {
			codeResult = result
			codePriority = priority
		}
	}
	if wxShareResult.name != "" {
		return wxShareResult, nil
	}
	if shareResult.name != "" {
		return shareResult, nil
	}
	if posterResult.name != "" {
		return posterResult, nil
	}
	// A page navigation title often names a functional module ("建发统一收银台")
	// rather than the program, so it is only used when nothing better exists.
	if navigationResult.name != "" {
		return navigationResult, nil
	}
	if gameResult.name != "" && (codeResult.name == "" || gamePriority < codePriority) {
		return gameResult, nil
	}
	if codeResult.name != "" {
		return codeResult, nil
	}
	return appNameResult{}, nil
}

func appNameFromPackageData(data []byte, files []*WxapkgFileItemStructure) string {
	return appNameFromPackageDataResult(data, files).name
}

func appNameFromPackageDataResult(data []byte, files []*WxapkgFileItemStructure) appNameResult {
	var navigationResult appNameResult
	var wxShareResult appNameResult
	var shareResult appNameResult
	sharePriority := int(^uint(0) >> 1)
	var posterResult appNameResult
	posterPriority := int(^uint(0) >> 1)
	var gameResult appNameResult
	gamePriority := int(^uint(0) >> 1)
	var codeResult appNameResult
	codePriority := int(^uint(0) >> 1)

	for _, file := range files {
		if file.name == "app-config.json" {
			configData, ok := packageEntryData(data, file, maxMetadataEntrySize)
			if !ok {
				continue
			}
			result := appNameFromConfigResult(configData)
			if result.source == appNameSourcePackageConfig {
				return result
			}
			if result.source == appNameSourceNavigationTitle && navigationResult.name == "" {
				navigationResult = result
			}
			continue
		}

		if base, ok := gameNameFilePriority[file.name]; ok {
			if priority := gameNamePriorityBase + base; priority < gamePriority {
				if gameData, ok := packageEntryData(data, file, maxMetadataEntrySize); ok {
					if result := appNameFromGameConfig(gameData); result.name != "" {
						gameResult = result
						gamePriority = priority
					}
				}
			}
			continue
		}

		priority, ok := codeEntryPriority(file.name)
		if !ok || priority >= codePriority {
			continue
		}
		codeData, ok := packageEntryDataSample(data, file, maxCodeMetadataSize)
		if !ok {
			continue
		}
		if sharePriority > priority {
			if result := appNameFromWxShare(codeData, isHomeShareEntry(file.name)); result.name != "" {
				if isHomeShareEntry(file.name) {
					return result
				}
				wxShareResult = result
			}
		}
		if sharePriority > priority {
			if result := appNameFromShareTitles(codeData); result.name != "" {
				shareResult = result
				sharePriority = priority
			}
		}
		if posterPriority > priority {
			if result := appNameFromPosterBrand(codeData); result.name != "" {
				posterResult = result
				posterPriority = priority
			}
		}
		result := appNameFromCodeContent(codeData)
		if result.name != "" {
			codeResult = result
			codePriority = priority
		}
	}
	if navigationResult.name != "" {
		return navigationResult
	}
	if wxShareResult.name != "" {
		return wxShareResult
	}
	if shareResult.name != "" {
		return shareResult
	}
	if posterResult.name != "" {
		return posterResult
	}
	if gameResult.name != "" && (codeResult.name == "" || gamePriority < codePriority) {
		return gameResult
	}
	if codeResult.name != "" {
		return codeResult
	}
	return appNameResult{}
}

func readWxapkgEntry(reader io.ReaderAt, entry wxapkgIndexEntry, maxSize uint32) ([]byte, error) {
	if entry.size > maxSize {
		return nil, errors.Errorf("wxapkg entry %q is too large: %d bytes", entry.name, entry.size)
	}
	data := make([]byte, int(entry.size))
	if err := readAtFull(reader, data, int64(entry.offset)); err != nil {
		return nil, err
	}
	return data, nil
}

func readWxapkgEntrySample(reader io.ReaderAt, entry wxapkgIndexEntry, maxSize uint32) ([]byte, error) {
	if entry.size <= maxSize {
		return readWxapkgEntry(reader, entry, maxSize)
	}

	headSize := int(maxSize / 2)
	tailSize := int(maxSize) - headSize
	head := make([]byte, headSize)
	tail := make([]byte, tailSize)
	if err := readAtFull(reader, head, int64(entry.offset)); err != nil {
		return nil, err
	}
	tailOffset := int64(entry.offset) + int64(entry.size) - int64(tailSize)
	if err := readAtFull(reader, tail, tailOffset); err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(head)+1+len(tail))
	data = append(data, head...)
	data = append(data, '\n')
	data = append(data, tail...)
	return data, nil
}

func packageEntryData(data []byte, file *WxapkgFileItemStructure, maxSize uint32) ([]byte, bool) {
	if file == nil || file.size > maxSize {
		return nil, false
	}
	start := uint64(file.offset)
	end := start + uint64(file.size)
	if end < start || end > uint64(len(data)) {
		return nil, false
	}
	return data[start:end], true
}

func packageEntryDataSample(data []byte, file *WxapkgFileItemStructure, maxSize uint32) ([]byte, bool) {
	if file == nil {
		return nil, false
	}
	if file.size <= maxSize {
		return packageEntryData(data, file, maxSize)
	}

	headSize := int(maxSize / 2)
	tailSize := int(maxSize) - headSize
	start := uint64(file.offset)
	end := start + uint64(file.size)
	if end < start || end > uint64(len(data)) {
		return nil, false
	}
	headEnd := start + uint64(headSize)
	tailStart := end - uint64(tailSize)
	if headEnd > end || tailStart < start {
		return nil, false
	}

	result := make([]byte, 0, headSize+1+tailSize)
	result = append(result, data[start:headEnd]...)
	result = append(result, '\n')
	result = append(result, data[tailStart:end]...)
	return result, true
}

func appNameFromConfig(data []byte) string {
	return appNameFromConfigResult(data).name
}

func appNameFromConfigResult(data []byte) appNameResult {
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return appNameResult{}
	}

	if result := appNameFromObject(config, appConfigNameFields, appNameSourcePackageConfig); result.name != "" {
		return result
	}
	for _, key := range []string{"global", "app", "appInfo", "miniProgram"} {
		if nested, ok := objectField(config, key); ok {
			if result := appNameFromObject(nested, appConfigNameFields, appNameSourcePackageConfig); result.name != "" {
				return result
			}
		}
	}

	// Real WeChat packages carry the program identity in the page window
	// titles, so prefer the entry page title over any other page title.
	if result := appNameFromEntryPageTitle(config); result.name != "" {
		return result
	}

	global, ok := objectField(config, "global")
	if ok {
		if window, ok := objectField(global, "window"); ok {
			if result := makeAppNameResult(stringField(window, []string{"navigationBarTitleText"}), appNameSourceNavigationTitle); result.name != "" {
				return result
			}
		}
	}

	// Last resort: the entry page has no usable title, so fall back to the most
	// repeated non-generic page title (e.g. a shared cashier title).
	return appNameFromPageTitleVote(config)
}

// appNameFromEntryPageTitle reads the navigation bar title of the entry page
// declared by app-config.json. Modern mini programs do not put a name in the
// global window config, but the entry page usually carries the program's own
// title while landing on a generic splash or login page.
func appNameFromEntryPageTitle(config map[string]interface{}) appNameResult {
	entryPage := stringField(config, []string{"entryPagePath"})
	if entryPage == "" {
		return appNameResult{}
	}

	page, ok := objectField(config, "page")
	if !ok {
		return appNameResult{}
	}
	pageConfig, ok := objectField(page, entryPage)
	if !ok {
		pageConfig, ok = objectField(page, trimPageExtension(entryPage))
	}
	if !ok {
		return appNameResult{}
	}
	window, ok := objectField(pageConfig, "window")
	if !ok {
		return appNameResult{}
	}
	result := makeAppNameResult(stringField(window, []string{"navigationBarTitleText"}), appNameSourceNavigationTitle)
	if result.name == "" {
		return appNameResult{}
	}
	return result
}

// trimPageExtension drops the ".html" suffix WeChat appends to page keys so an
// entryPagePath without the suffix still resolves.
func trimPageExtension(page string) string {
	return strings.TrimSuffix(page, ".html")
}

// appNameFromPageTitleVote picks the most repeated non-generic page title.
// It is a low-confidence fallback used only when neither an explicit name field
// nor the entry page title is available.
func appNameFromPageTitleVote(config map[string]interface{}) appNameResult {
	page, ok := objectField(config, "page")
	if !ok {
		return appNameResult{}
	}

	type vote struct {
		name  string
		count int
	}
	votes := make(map[string]*vote)
	for _, value := range page {
		pageConfig, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		window, ok := objectField(pageConfig, "window")
		if !ok {
			continue
		}
		result := makeAppNameResult(stringField(window, []string{"navigationBarTitleText"}), appNameSourceNavigationTitle)
		if result.name == "" {
			continue
		}
		if existing, ok := votes[result.name]; ok {
			existing.count++
		} else {
			votes[result.name] = &vote{name: result.name, count: 1}
		}
	}

	var best *vote
	for _, candidate := range votes {
		// Require a repeated title: a single occurrence is indistinguishable
		// from a one-off page label.
		if candidate.count < 2 {
			continue
		}
		if best == nil || candidate.count > best.count ||
			(candidate.count == best.count && candidate.name < best.name) {
			best = candidate
		}
	}
	if best == nil {
		return appNameResult{}
	}
	return appNameResult{name: best.name, source: appNameSourceNavigationTitle}
}

// appNameFromGameConfig extracts a name from a mini game config file
// (project.json / game.json) and its page table entries.
func appNameFromGameConfig(data []byte) appNameResult {
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return appNameResult{}
	}

	if result := appNameFromObject(config, appConfigNameFields, appNameSourcePackageConfig); result.name != "" {
		return result
	}
	for _, key := range []string{"game", "gameInfo", "app", "appInfo", "miniProgram", "project"} {
		if nested, ok := objectField(config, key); ok {
			if result := appNameFromObject(nested, appConfigNameFields, appNameSourcePackageConfig); result.name != "" {
				return result
			}
		}
	}
	return appNameResult{}
}

// appNameFromLocalConfig extracts a name from the JSON metadata WeChat stores
// next to a package (appinfo.json and friends).
func appNameFromLocalConfig(data []byte) appNameResult {
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return appNameResult{}
	}

	if result := appNameFromObject(config, localNameFields, appNameSourceLocalMetadata); result.name != "" {
		return result
	}
	for _, key := range []string{"app", "appInfo", "miniProgram", "program", "data", "info"} {
		if nested, ok := objectField(config, key); ok {
			if result := appNameFromObject(nested, localNameFields, appNameSourceLocalMetadata); result.name != "" {
				return result
			}
		}
	}
	return appNameResult{}
}

func appNameFromObject(object map[string]interface{}, fields []string, source string) appNameResult {
	if object == nil {
		return appNameResult{}
	}
	return makeAppNameResult(stringField(object, fields), source)
}

func objectField(object map[string]interface{}, field string) (map[string]interface{}, bool) {
	if object == nil {
		return nil, false
	}
	for key, value := range object {
		if !strings.EqualFold(key, field) {
			continue
		}
		nested, ok := value.(map[string]interface{})
		return nested, ok
	}
	return nil, false
}

func stringField(object map[string]interface{}, fields []string) string {
	if object == nil {
		return ""
	}
	for _, field := range fields {
		for key, value := range object {
			if !strings.EqualFold(key, field) {
				continue
			}
			if name, ok := value.(string); ok {
				return name
			}
		}
	}
	return ""
}

// appNameFromShareTitles extracts the mini program name from share callback
// config, e.g. `onShareAppMessage(() => ({title:"<name>", path:"/pages/index/index"}))`.
// The card title is what users see for the program, so it beats a plain page
// navigation title. The callback pointing at the home page wins, because other
// callbacks often advertise one activity ("<brand>会员活动") instead of the
// program itself.
func appNameFromShareTitles(data []byte) appNameResult {
	matches := shareTitlePattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return appNameResult{}
	}

	best := ""
	for _, match := range matches {
		title := makeAppNameResult(string(match[1]), appNameSourceShareCard)
		if title.name == "" || isRejectedShareTitle(title.name) {
			continue
		}
		if shareHomePathPattern.MatchString(string(match[2])) {
			return title
		}
		if best == "" {
			best = title.name
		}
	}
	if best == "" {
		return appNameResult{}
	}
	return appNameResult{name: best, source: appNameSourceShareCard}
}

// appNameFromWxShare extracts the title passed to the project share helper,
// e.g. `wxShareConfig:function(){this.wxShare({title:"<name>"})}`. This is the
// strongest signal because the developer writes it as the program title.
//
// sharePageHome reports whether the containing page is the program home page;
// home page titles win over other pages, which often advertise a sub module
// ("<brand>积分商城", "<brand>会员天地").
func appNameFromWxShare(data []byte, sharePageHome bool) appNameResult {
	matches := wxSharePattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return appNameResult{}
	}

	best := appNameResult{}
	for _, match := range matches {
		result := makeAppNameResult(string(match[1]), appNameSourceWxShare)
		if result.name == "" || isRejectedShareTitle(result.name) {
			continue
		}
		if sharePageHome {
			return result
		}
		if best.name == "" {
			best = result
		}
	}
	return best
}

// isHomeShareEntry reports whether a code entry belongs to the program home
// page, judged from its path such as "pages/index/app-service.js".
func isHomeShareEntry(name string) bool {
	lower := strings.ToLower(strings.TrimPrefix(name, "/"))
	dir := lower
	if separator := strings.LastIndexByte(lower, '/'); separator >= 0 {
		dir = lower[:separator]
	}
	for _, home := range []string{"pages/index", "pages/home", "pages/main", "pages/entry", "pages/app", "index", "home"} {
		if dir == home || strings.HasSuffix(dir, "/"+home) {
			return true
		}
	}
	// A top level "main.js" / "entry.js" is the program entry script.
	for _, entry := range []string{"main.js", "entry.js"} {
		if lower == entry || strings.HasSuffix(lower, "/"+entry) && !strings.Contains(dir, "pages/") {
			return true
		}
	}
	return false
}

// appNameFromPosterBrand extracts the brand label drawn on a share poster.
// Poster text such as "建发房产钻石会" names the program itself, whereas page
// navigation titles frequently name a functional module ("建发统一收银台").
func appNameFromPosterBrand(data []byte) appNameResult {
	matches := posterBrandPattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return appNameResult{}
	}

	// Prefer the longest usable label: poster branding carries the full name,
	// while shorter labels are usually captions or button text.
	best := appNameResult{}
	for _, match := range matches {
		result := makeAppNameResult(string(match[1]), appNameSourcePosterBrand)
		if result.name == "" || isRejectedShareTitle(result.name) {
			continue
		}
		if len([]rune(result.name)) > len([]rune(best.name)) {
			best = result
		}
	}
	return best
}

// isRejectedShareTitle drops share titles that cannot be a program name, such
// as a raw wxid or a one-off promotional line.
func isRejectedShareTitle(name string) bool {
	if reWxId.MatchString(strings.ToLower(name)) || strings.ContainsAny(name, "/\\") {
		return true
	}
	if isPromotionalTitle(name) {
		return true
	}
	return !isLikelyCodeName(name)
}

// isPromotionalTitle reports titles that advertise an action instead of
// naming the program, e.g. "限时秒杀" or "立即领取".
func isPromotionalTitle(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, keyword := range []string{
		"秒杀", "限时", "立即", "马上", "抢购", "特价", "促销", "免费领",
		"点击", "领取", "参与", "抽奖", "报名", "下单", "优惠", "红包",
	} {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	switch lower {
	case "share", "分享", "分享标题", "title", "标题", "test", "测试":
		return true
	}
	return false
}

// appNameFromCodeContent scans compiled code for a name hint.
func appNameFromCodeContent(data []byte) appNameResult {
	for _, pattern := range codeNamePatterns {
		match := pattern.FindSubmatch(data)
		if len(match) < 2 {
			continue
		}
		result := makeAppNameResult(string(match[1]), appNameSourceCodeCandidate)
		if result.name == "" {
			continue
		}
		if reWxId.MatchString(strings.ToLower(result.name)) ||
			strings.ContainsAny(result.name, "/\\") ||
			strings.EqualFold(result.name, "netscape") ||
			strings.EqualFold(result.name, "mozilla") {
			continue
		}
		if !isLikelyCodeName(result.name) {
			continue
		}
		return result
	}
	return appNameResult{}
}

func isLikelyCodeName(name string) bool {
	runes := []rune(name)
	if len(runes) >= 4 {
		return true
	}
	for _, value := range runes {
		if value >= 0x4e00 && value <= 0x9fff {
			return true
		}
	}
	return false
}

// codeEntryPriority reports how strongly a file should be trusted as a name
// source. Every code file is ranked below the structural sources so that a
// regex guess never overrides an explicit config or page title.
func codeEntryPriority(name string) (int, bool) {
	name = strings.ToLower(strings.TrimPrefix(name, "/"))
	if priority, ok := codeNameFilePriority[name]; ok {
		return codeNamePriorityBase + priority, true
	}
	if separator := strings.LastIndexByte(name, '/'); separator >= 0 {
		if priority, ok := codeNameFilePriority[name[separator+1:]]; ok {
			return codeNamePriorityBase + 10 + priority, true
		}
	}
	return 0, false
}

func isGenericAppTitle(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "\u9996\u9875", "\u4e3b\u9875", "home", "index", "main", "welcome",
		"default", "login", "signin", "\u6211\u7684", "\u4e2a\u4eba\u4e2d\u5fc3",
		"\u8bbe\u7f6e", "\u6d88\u606f", "\u53d1\u73b0", "loading", "cart",
		"profile", "settings", "search", "orders", "order",
		"\u52a0\u8f7d\u4e2d", "\u52a0\u8f7d\u4e2d...", "\u652f\u4ed8",
		"\u5fae\u4fe1\u652f\u4ed8", "\u8d2d\u7269\u8f66", "\u63d0\u793a",
		"\u767b\u5f55", "\u4f1a\u5458\u767b\u5f55", "\u641c\u7d22", "\u8ba2\u5355",
		"\u8ba2\u5355\u5217\u8868", "\u8ba2\u5355\u8be6\u60c5", "\u6211\u7684\u8ba2\u5355",
		"\u6536\u8d27\u5730\u5740", "\u65b0\u589e\u6536\u8d27\u5730\u5740",
		"\u9009\u62e9\u95e8\u5e97", "\u9009\u62e9\u57ce\u5e02", "\u70b9\u9910",
		"\u624b\u673a\u70b9\u9910", "\u4e0b\u5355\u9875", "\u4f18\u60e0\u5238\u9875",
		"\u4f1a\u5458\u4e2d\u5fc3", "\u6d4b\u8bd5\u7ed3\u679c", "\u6d4b\u8bd5\u8be6\u60c5",
		"\u6d4b\u8bd5\u5386\u53f2", "\u66f4\u591a\u7ed3\u679c":
		return true
	default:
		return false
	}
}

func makeAppNameResult(name, source string) appNameResult {
	name = cleanAppName(name)
	if name == "" || isGenericAppTitle(name) {
		return appNameResult{}
	}
	return appNameResult{name: name, source: source}
}

func cleanAppName(name string) string {
	name = strings.Join(strings.Fields(strings.TrimSpace(name)), " ")
	if name == "" {
		return ""
	}
	runes := []rune(name)
	if len(runes) > maxAppNameLength {
		return string(runes[:maxAppNameLength])
	}
	return name
}

func wxIDFromPath(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	for _, component := range strings.Split(path, "/") {
		if reWxId.MatchString(component) {
			return component
		}
	}
	return ""
}

func readLocalAppName(path, wxid string) appNameResult {
	root := appIDRootForPath(path, wxid)
	if root == "" {
		return appNameResult{}
	}
	localRoot := filepath.Join(filepath.Dir(filepath.Dir(root)), "local")
	localDir := filepath.Join(localRoot, wxid)
	if info, err := os.Stat(localDir); err != nil || !info.IsDir() {
		entries, err := os.ReadDir(localRoot)
		if err != nil {
			return appNameResult{}
		}
		for _, entry := range entries {
			if entry.IsDir() && strings.EqualFold(entry.Name(), wxid) {
				localDir = filepath.Join(localRoot, entry.Name())
				break
			}
		}
	}

	metadataEntries, err := os.ReadDir(localDir)
	if err != nil {
		return appNameResult{}
	}
	for _, wanted := range knownLocalMetadataFiles {
		for _, entry := range metadataEntries {
			if entry.IsDir() || !strings.EqualFold(entry.Name(), wanted) {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.Size() < 0 || info.Size() > int64(maxMetadataEntrySize) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(localDir, entry.Name()))
			if err != nil {
				continue
			}
			if result := appNameFromLocalConfig(data); result.name != "" {
				return result
			}
		}
	}
	return appNameResult{}
}

func appIDRootForPath(path, wxid string) string {
	if wxid == "" {
		wxid = wxIDFromPath(path)
	}
	if wxid == "" {
		return ""
	}
	current := filepath.Clean(path)
	if info, err := os.Stat(current); err == nil && !info.IsDir() {
		current = filepath.Dir(current)
	}
	for {
		if strings.EqualFold(filepath.Base(current), wxid) {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		current = parent
	}
}

func listDirectWxapkgFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".wxapkg") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
	}
	return files, nil
}

func wxapkgFilePriority(path string) int {
	switch strings.ToLower(filepath.Base(path)) {
	case "__app__.wxapkg":
		return 0
	case "__full__.wxapkg":
		return 1
	case "__subpackage__.wxapkg":
		return 2
	case "__plugincode__.wxapkg":
		return 4
	default:
		return 3
	}
}

func fileModTimeNano(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.ModTime().UnixNano()
}

func chooseMainWxapkg(files []string) string {
	if len(files) == 0 {
		return ""
	}
	candidates := append([]string(nil), files...)
	sort.SliceStable(candidates, func(i, j int) bool {
		pi, pj := wxapkgFilePriority(candidates[i]), wxapkgFilePriority(candidates[j])
		if pi != pj {
			return pi < pj
		}
		ti, tj := fileModTimeNano(candidates[i]), fileModTimeNano(candidates[j])
		if ti != tj {
			return ti > tj
		}
		return strings.ToLower(candidates[i]) < strings.ToLower(candidates[j])
	})
	return candidates[0]
}

func compareVersionNames(left, right string) int {
	leftDigits := left != ""
	rightDigits := right != ""
	for _, value := range left {
		if value < '0' || value > '9' {
			leftDigits = false
			break
		}
	}
	for _, value := range right {
		if value < '0' || value > '9' {
			rightDigits = false
			break
		}
	}
	if leftDigits && rightDigits {
		leftTrimmed := strings.TrimLeft(left, "0")
		rightTrimmed := strings.TrimLeft(right, "0")
		if leftTrimmed == "" {
			leftTrimmed = "0"
		}
		if rightTrimmed == "" {
			rightTrimmed = "0"
		}
		if len(leftTrimmed) != len(rightTrimmed) {
			if len(leftTrimmed) > len(rightTrimmed) {
				return 1
			}
			return -1
		}
		if leftTrimmed != rightTrimmed {
			if leftTrimmed > rightTrimmed {
				return 1
			}
			return -1
		}
		return 0
	}
	if left == right {
		return 0
	}
	if left > right {
		return 1
	}
	return -1
}

func findMainWxapkg(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if !info.IsDir() {
		return path
	}

	if files, err := listDirectWxapkgFiles(path); err == nil && len(files) > 0 {
		return chooseMainWxapkg(files)
	}

	type versionCandidate struct {
		path    string
		version string
		modTime int64
	}
	entries, err := os.ReadDir(path)
	if err == nil {
		candidates := make([]versionCandidate, 0)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			versionPath := filepath.Join(path, entry.Name())
			files, err := listDirectWxapkgFiles(versionPath)
			if err != nil || len(files) == 0 {
				continue
			}
			mainPath := chooseMainWxapkg(files)
			candidates = append(candidates, versionCandidate{
				path:    mainPath,
				version: entry.Name(),
				modTime: fileModTimeNano(mainPath),
			})
		}
		if len(candidates) > 0 {
			sort.SliceStable(candidates, func(i, j int) bool {
				if candidates[i].modTime != candidates[j].modTime {
					return candidates[i].modTime > candidates[j].modTime
				}
				if versionCompare := compareVersionNames(candidates[i].version, candidates[j].version); versionCompare != 0 {
					return versionCompare > 0
				}
				return strings.ToLower(candidates[i].path) < strings.ToLower(candidates[j].path)
			})
			return candidates[0].path
		}
	}

	files, err := ListFilesWithExtension(path, ".wxapkg")
	if err != nil || len(files) == 0 {
		return ""
	}
	return chooseMainWxapkg(files)
}

func appNameForPathResult(path, wxid string) appNameResult {
	if result := readLocalAppName(path, wxid); result.name != "" {
		return result
	}

	// Collect the best result from every package before deciding. Returning on
	// the first non-empty hit is wrong: the main bundle usually only exposes a
	// functional page title, while the home page sub package declares the real
	// program title through wxShare.
	var best appNameResult
	bestRank := -1
	for _, packagePath := range packageCandidates(path) {
		result, err := readWxapkgAppNameResult(packagePath, wxid)
		if err != nil || result.name == "" {
			continue
		}
		rank := appNameSourceRank(result.source)
		if rank > bestRank {
			best = result
			bestRank = rank
		}
		// Nothing outranks a share-helper title, so stop searching.
		if result.source == appNameSourceWxShare {
			return result
		}
	}
	return best
}

// appNameSourceRank orders name sources by reliability; higher wins.
func appNameSourceRank(source string) int {
	switch source {
	case appNameSourceWxShare:
		return 60
	case appNameSourceShareCard:
		return 50
	case appNameSourcePosterBrand:
		return 40
	case appNameSourcePackageConfig:
		return 20
	case appNameSourceNavigationTitle:
		return 10
	default:
		return 0
	}
}

// packageCandidates returns the wxapkg files worth scanning, main package
// first. Sub packages matter: a program's own title is often declared only in
// the home page sub package (`_pages_index_.wxapkg`), not in `__APP__.wxapkg`.
func packageCandidates(path string) []string {
	main := findMainWxapkg(path)
	if main == "" {
		return nil
	}
	candidates := []string{main}

	files := []string{}
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		if direct, err := listDirectWxapkgFiles(path); err == nil && len(direct) > 0 {
			files = append(files, direct...)
		} else {
			all, _ := ListFilesWithExtension(path, ".wxapkg")
			files = append(files, all...)
		}
	}

	// Sub packages are named after their page root, so the home page sub
	// package sorts ahead of the rest.
	sort.SliceStable(files, func(i, j int) bool {
		pi, pj := packageScanPriority(files[i]), packageScanPriority(files[j])
		if pi != pj {
			return pi < pj
		}
		return strings.ToLower(files[i]) < strings.ToLower(files[j])
	})
	for _, file := range files {
		if file != main {
			candidates = append(candidates, file)
		}
	}
	return candidates
}

// packageScanPriority orders packages so the most name-bearing ones are read
// first: main bundle, then the home page and other page sub packages, then
// plugin code.
func packageScanPriority(file string) int {
	base := strings.ToLower(filepath.Base(file))
	switch {
	case base == "__app__.wxapkg":
		return 0
	case base == "__full__.wxapkg":
		return 1
	case strings.Contains(base, "pages_index") || strings.Contains(base, "pages_home") ||
		strings.Contains(base, "pages_main") || strings.Contains(base, "pages_app"):
		return 2
	case base == "__plugincode__.wxapkg":
		return 9
	case strings.HasPrefix(base, "__"):
		return 5
	default:
		return 3
	}
}

func appNameForPath(path, wxid string) string {
	return appNameForPathResult(path, wxid).name
}
