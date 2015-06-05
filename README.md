wfscanner
=========

wfscanner is a frontend to Mozilla MIG and other tools that identifies
and inventories arbitrary software installations on servers. It uses a
package "descriptor" to provide a fingerprint for a file, and based on this
descriptor conducts scans for installations matching the fingerprint and
returns version details.

It also has a secondary program, wfs2mozdef which converts results from
wfs into MozDef vulnerability documents, and incorporates additional
information such as CVE descriptions and CVSS values.
