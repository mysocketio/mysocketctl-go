package mysqlworkbench

import (
	"encoding/xml"
	"fmt"

	uuid "github.com/satori/go.uuid"
)

func ConnectionsXML(host string, port int, sslCertPath, sslKeyPath, dbName string) (string, error) {
	id := uuid.NewV4().String()
	conns := xmlDoc{
		GrtFormat: "2.0",
		Connections: conns{
			attrs: attrs{Ptr: "abc123", Type: "list", ContentType: "object", ContentStructName: "db.mgmt.Connection"},
			Connections: []conn{
				{
					attrs: attrs{Type: "object", StructName: "db.mgmt.Connection", ID: id, StructChecksum: "def456"},
					Link: link{
						attrs: attrs{Type: "object", StructName: "db.mgmt.Driver", Key: "driver"},
						Data:  "com.mysql.rdbms.mysql.driver.native",
					},
					Values: []value{
						{
							attrs: attrs{Type: "string", Key: "name"},
							Data:  host,
						},
						{
							attrs: attrs{Type: "string", Key: "hostIdentifier"},
							Data:  fmt.Sprintf("Mysql@%s:%d", host, port),
						},
					},
					NestedValues: []params{
						{
							attrs: attrs{Ptr: "abc123", Type: "dict", Key: "modules"},
						},
						{
							attrs: attrs{Ptr: "abc123", Type: "dict", Key: "parameterValues"},
							Values: []value{
								{
									attrs: attrs{Type: "string", Key: "SQL_MODE"},
								},
								{
									attrs: attrs{Type: "string", Key: "hostName"},
									Data:  host,
								},
								{
									attrs: attrs{Type: "string", Key: "password"},
								},
								{
									attrs: attrs{Type: "int", Key: "port"},
									Data:  fmt.Sprint(port),
								},
								{
									attrs: attrs{Type: "string", Key: "schema"},
									Data:  dbName,
								},
								{
									attrs: attrs{Type: "string", Key: "sslCA"},
								},
								{
									attrs: attrs{Type: "string", Key: "sslCert"},
									Data:  sslCertPath,
								},
								{
									attrs: attrs{Type: "string", Key: "sslCipher"},
								},
								{
									attrs: attrs{Type: "string", Key: "sslKey"},
									Data:  sslKeyPath,
								},
								{
									attrs: attrs{Type: "int", Key: "useSSL"},
									Data:  "1",
								},
								{
									attrs: attrs{Type: "string", Key: "userName"},
									Data:  "placeholder",
								},
							},
						},
					},
				},
			},
		},
	}
	output, err := xml.MarshalIndent(&conns, "", "    ")
	if err != nil {
		return "", fmt.Errorf("error generating MySQL Workbench connections.xml: %w", err)
	}

	return xml.Header + string(output), nil
}

// Example:
//
//     <?xml version="1.0"?>
//     <data grt_format="2.0">
//       <value _ptr_="abc123" type="list" content-type="object" content-struct-name="db.mgmt.Connection">
//         <value type="object" struct-name="db.mgmt.Connection" id="7e4b13cc-a48c-11ec-8ef1-02a8c4b46216" struct-checksum="def456">
//           <link type="object" struct-name="db.mgmt.Driver" key="driver">com.mysql.rdbms.mysql.driver.native</link>
//           <value type="string" key="name">db.api.staging.us.mysocket</value>
//           <value type="string" key="hostIdentifier">Mysql@db.api.staging.us.mysocket:30583</value>
//           <value type="int" key="isDefault">0</value>
//           <value _ptr_="abc123" type="dict" key="modules"/>
//           <value _ptr_="abc123" type="dict" key="parameterValues">
//             <value type="string" key="SQL_MODE"></value>
//             <value type="string" key="hostName">db.api.staging.us.mysocket</value>
//             <value type="string" key="password"></value>
//             <value type="int" key="port">30583</value>
//             <value type="string" key="schema">mysocket</value>
//             <value type="string" key="sslCA"></value>
//             <value type="string" key="sslCert">/Users/rollie/.mysocketio/still-voice-9340.edge.mysocket.io.crt</value>
//             <value type="string" key="sslCipher"></value>
//             <value type="string" key="sslKey">/Users/rollie/.mysocketio/still-voice-9340.edge.mysocket.io.key</value>
//             <value type="int" key="useSSL">1</value>
//             <value type="string" key="userName">placeholder</value>
//           </value>
//         </value>
//       </value>
//     </data>
type xmlDoc struct {
	XMLName     xml.Name `xml:"data"`
	GrtFormat   string   `xml:"grt_format,attr"`
	Connections conns
}

type conns struct {
	XMLName     xml.Name `xml:"value"`
	Connections []conn
	attrs
}

type conn struct {
	XMLName      xml.Name `xml:"value"`
	Link         link
	Values       []value
	NestedValues []params
	attrs
}

type link struct {
	XMLName xml.Name `xml:"link"`
	Data    string   `xml:",chardata"`
	attrs
}

type value struct {
	XMLName xml.Name `xml:"value"`
	Data    string   `xml:",chardata"`
	attrs
}

type params struct {
	XMLName xml.Name `xml:"value"`
	Values  []value  `xml:",omitempty"`
	attrs
}

type attrs struct {
	Ptr               string `xml:"_ptr_,attr,omitempty"`
	Type              string `xml:"type,attr,omitempty"`
	ContentType       string `xml:"content-type,attr,omitempty"`
	ContentStructName string `xml:"content-struct-name,attr,omitempty"`
	StructName        string `xml:"struct-name,attr,omitempty"`
	ID                string `xml:"id,attr,omitempty"`
	StructChecksum    string `xml:"struct-checksum,attr,omitempty"`
	Key               string `xml:"key,attr,omitempty"`
}
