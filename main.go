package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"text/template"
)

const (
	TRIVY_RESULT_DIR     = "trivy-result"
	TRIVY_RESULT_OLD_DIR = "trivy-result-old"
)

type TrivyJSONResultVulnerability struct {
	VulnerabilityID  string
	PkgID            string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Layer            map[string]string
	SeveritySource   string
	PrimaryURL       string
	DataSource       map[string]string
	Title            string
	Description      string
	Severity         string
	CweIDs           []string
	CVSS             map[string]interface{}
	References       []string
	PublishedDate    string
	LastModifiedData string
}

type TrivyJSONResult struct {
	Vulnerabilities []TrivyJSONResultVulnerability
}

type TrivyJSON struct {
	SchemaVersion int
	ArtifactName  string
	Results       []TrivyJSONResult
}

type Vulnerabililty struct {
	PkgID            string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	ID               string
	USN              string
	Links            []string
	Title            string
	Description      string
	Severity         string
}

func fetchUSNFromCVE(cveId string) (string, error) {
	url, err := url.JoinPath("https://ubuntu.com/security/cves/", cveId+".json")
	if err != nil {
		return "", err
	}
	log.Printf("GET %s\n", url)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(resp.Body)
	body := map[string]interface{}{}
	if err := dec.Decode(&body); err != nil {
		return "", err
	}
	notices, ok := body["notices"].([]interface{})
	if !ok {
		return "", errors.New("Invalid JSON")
	}
	usn := ""
	for _, rawNotice := range notices {
		notice := rawNotice.(map[string]interface{})

		typ, ok := notice["type"].(string)
		if !ok || typ != "USN" {
			continue
		}
		usn, ok = notice["id"].(string)
		if !ok {
			continue
		}
		break
	}
	if usn == "" {
		return "", errors.New("USN not found")
	}
	return usn, nil
}

func NewVulnerability(j *TrivyJSONResultVulnerability) *Vulnerabililty {
	id := j.VulnerabilityID
	usnId, err := fetchUSNFromCVE(id)
	if err != nil {
		log.Printf("Couldn't fetch USN from CVE: %s: %v", id, err)
	}
	usnLink := ""
	if usnId != "" {
		usnLink = path.Join("https://ubuntu.com/security/notices/", usnId)
	}
	links := []string{}
	if usnLink != "" {
		links = append(links, usnLink)
	}
	links = append(links, j.PrimaryURL)

	return &Vulnerabililty{
		PkgID:            j.PkgID,
		PkgName:          j.PkgName,
		InstalledVersion: j.InstalledVersion,
		FixedVersion:     j.FixedVersion,
		ID:               id,
		USN:              usnId,
		Links:            links,
		Title:            j.Title,
		Description:      j.Description,
		Severity:         j.Severity,
	}
}

func parseTrivyJSON(reader io.Reader) (*TrivyJSON, error) {
	dec := json.NewDecoder(reader)
	var res TrivyJSON
	if err := dec.Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

func diffTrivyVulnerabilities(oldVuls []TrivyJSONResultVulnerability, newVuls []TrivyJSONResultVulnerability) []TrivyJSONResultVulnerability {
	m := map[string]TrivyJSONResultVulnerability{}
	for _, v := range oldVuls {
		m[v.VulnerabilityID+v.PkgID] = v
	}

	res := []TrivyJSONResultVulnerability{}
	for _, v := range newVuls {
		_, ok := m[v.VulnerabilityID+v.PkgID]
		if !ok {
			res = append(res, v)
		}
	}

	return res
}

func loadTrivyVulnerabilities(fileName string) ([]TrivyJSONResultVulnerability, error) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Printf("Couldn't open file (%s, %s). Treated as no results.", fileName, err)
		return []TrivyJSONResultVulnerability{}, nil
	}
	defer file.Close()

	j, err := parseTrivyJSON(file)
	if err != nil {
		return nil, err
	}

	if len(j.Results) != 1 {
		return nil, fmt.Errorf("Invalid # of JSON results: %d", len(j.Results))
	}

	return j.Results[0].Vulnerabilities, nil
}

func generateHTML(vuls []*Vulnerabililty) (string, error) {
	const tpl = `
<html>
<head>
<title>daily-usn</title>
<style>
table,
td {
    border: 1px solid #333;
}

thead,
tfoot {
    background-color: #333;
    color: #fff;
}
</style>
</head>
<body>
<table>
<thead>
	<tr>
		<th>Package Name</th>
		<th>Vulnerability ID</th>
		<th>USN ID</th>
		<th>Severity</th>
		<th>Installed Version </th>
		<th>Fixed Version</th>
		<th>Links</th>
	</tr>
</thead>
<tbody>
{{ range .Vuls }}
<tr>
	<td>{{ .PkgName }}</td>
	<td>{{ .ID }}</td>
	<td>{{ .USN }}</td>
	<td>{{ .Severity }}</td>
	<td>{{ .InstalledVersion }}</td>
	<td>{{ .FixedVersion }}</td>
	<td>{{ range .Links }}<a href="{{ . }}">{{ . }}</a><br /> {{ end }}</td>
</tr>
{{ end }}
</tbody>
</table>
</body>
</html>
`
	t, err := template.New("webpage").Parse(tpl)
	if err != nil {
		return "", err
	}
	data := struct {
		Vuls []*Vulnerabililty
	}{
		Vuls: vuls,
	}
	b := bytes.NewBufferString("")
	if err := t.Execute(b, data); err != nil {
		return "", err
	}

	return b.String(), nil
}

func process() error {
	newFiles, err := os.ReadDir(TRIVY_RESULT_DIR)
	if err != nil {
		return err
	}

	for _, file := range newFiles {
		fileName := file.Name()

		newFilePath := filepath.Join(TRIVY_RESULT_DIR, fileName)
		oldFilePath := filepath.Join(TRIVY_RESULT_OLD_DIR, fileName)
		log.Printf("new_file_path = %s\n", newFilePath)
		log.Printf("old_file_path = %s\n", oldFilePath)

		newVuls, err := loadTrivyVulnerabilities(newFilePath)
		if err != nil {
			return err
		}
		oldVuls, err := loadTrivyVulnerabilities(oldFilePath)
		if err != nil {
			return err
		}
		trivyVuls := diffTrivyVulnerabilities(oldVuls, newVuls)

		vuls := []*Vulnerabililty{}
		for _, trivyVul := range trivyVuls {
			vul := NewVulnerability(&trivyVul)
			vuls = append(vuls, vul)
		}
		log.Printf(">>> %d %v\n", len(vuls), vuls[0])

		htmlTableRows, err := generateHTML(vuls)
		if err != nil {
			return err
		}
		fmt.Printf("<table>%s</table>", htmlTableRows)
	}

	return nil
}

func main() {
	err := process()
	if err != nil {
		log.Fatal(err)
	}
}
