#####################
## AUTHENTICATE TO MS GRAPH API & CONNECT DATABASE

print("Authenticating to Microsoft's API...\n\r\n\r")

import sqlite3
con = sqlite3.connect("DefenderVulns.db")
cur = con.cursor()

import json
import urllib.request
import urllib.parse
import time
from prettytable import PrettyTable

current_epoch = int(time.time())

tenantId = ''
appId = ''
appSecret = ''

url = "https://login.microsoftonline.com/%s/oauth2/token" % (tenantId)

resourceAppIdUri = 'https://api.securitycenter.microsoft.com'

body = {
    'resource' : resourceAppIdUri,
    'client_id' : appId,
    'client_secret' : appSecret,
    'grant_type' : 'client_credentials'
}

data = urllib.parse.urlencode(body).encode("utf-8")

req = urllib.request.Request(url, data)
response = urllib.request.urlopen(req)
jsonResponse = json.loads(response.read())
aadToken = jsonResponse["access_token"]


#####################
## LOOP FOR EACH SEVERITY

CountBySeverity = []

i = 1
while i <= 3:

  if i == 1:
    severity = "Critical"
  if i == 2:
    severity = "High"
  if i == 3:
    severity = "Medium"

  print("Pulling " + severity + " findings...\n\r")

  #####################
  ## GET VULNS

  url = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities?$filter=severity+eq+'" + severity + "'"

  headers = { 
      'Content-Type' : 'application/json',
      'Accept' : 'application/json',
      'Authorization' : "Bearer " + aadToken
  }

  req = urllib.request.Request(url, headers=headers)
  response = urllib.request.urlopen(req)

  jsonResponse = json.loads(response.read())

  results = jsonResponse["value"]

  print("... " + str(len(results)) + " " + severity + " records ...\r\n\r\n")

  CountBySeverity.append(severity)
  CountBySeverity.append(len(results))

  ## INSERT VULN DATA

  print("Writing " + severity + " findings to the database...\n\r\n\r")

  for result in results:
       sql = ''' INSERT OR IGNORE INTO VulnsByMachine (id,cveId,machineId,fixingKbId,productName,productVendor,productVersion,severity,InsertDatetime) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?) '''
       data = (result["id"], result["cveId"], result["machineId"], result["fixingKbId"], result["productName"], result["productVendor"], result["productVersion"], result["severity"],current_epoch)
       cur.execute(sql, data)
       con.commit()

       cur.execute('''UPDATE VulnsByMachine SET (id,cveId,machineId,fixingKbId,productName,productVendor,productVersion,severity,LastUpdated) = (?,?,?,?,?,?,?,?,?) WHERE id = ?''', (result["id"], result["cveId"], result["machineId"], result["fixingKbId"], result["productName"], result["productVendor"], result["productVersion"], result["severity"],current_epoch,result["id"],))
       con.commit()

  i += 1

#####################
## GET VULN DETAILS

print("Getting vulnerability details and writing to the database...\n\r\n\r")

remainingrecords = 8000

totalrecords = 0

while remainingrecords >= 1:

     url = "https://api.securitycenter.microsoft.com/api/Vulnerabilities?$skip=" + str(totalrecords)

     headers = { 
         'Content-Type' : 'application/json',
         'Accept' : 'application/json',
         'Authorization' : "Bearer " + aadToken
     }

     req = urllib.request.Request(url, headers=headers)
     response = urllib.request.urlopen(req)

     jsonResponse2 = json.loads(response.read())

     totalrecords = totalrecords + len(jsonResponse2["value"])

     remainingrecords = len(jsonResponse2["value"])


     vulndetailsresults = jsonResponse2["value"]

     for vulndetails in vulndetailsresults:
          if vulndetails["exposedMachines"] >= 1:
            sql = ''' INSERT OR IGNORE INTO VulnDetails (id,name,description,severity,cvssV3,cvssVector,exposedMachines,publishedOn,updatedOn,firstDetected,publicExploit,exploitVerified,exploitInKit,cveSupportability,epss,InsertDatetime) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''
            data = (vulndetails["id"], vulndetails["name"], vulndetails["description"], vulndetails["severity"], vulndetails["cvssV3"], vulndetails["cvssVector"], vulndetails["exposedMachines"], vulndetails["publishedOn"], vulndetails["updatedOn"], vulndetails["firstDetected"], vulndetails["publicExploit"], vulndetails["exploitVerified"], vulndetails["exploitInKit"], vulndetails["cveSupportability"], vulndetails["epss"], current_epoch)
            cur.execute(sql, data)
            con.commit()

            cur.execute('''UPDATE VulnDetails SET (id,name,description,severity,cvssV3,cvssVector,exposedMachines,publishedOn,updatedOn,firstDetected,publicExploit,exploitVerified,exploitInKit,cveSupportability,epss,LastUpdated) = (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) WHERE id = ?''', (vulndetails["id"], vulndetails["name"], vulndetails["description"], vulndetails["severity"], vulndetails["cvssV3"], vulndetails["cvssVector"], vulndetails["exposedMachines"], vulndetails["publishedOn"], vulndetails["updatedOn"], vulndetails["firstDetected"], vulndetails["publicExploit"], vulndetails["exploitVerified"], vulndetails["exploitInKit"], vulndetails["cveSupportability"], vulndetails["epss"], current_epoch, result["id"],))
            con.commit()
     

#####################
## GET MACHINES

print("Getting hosts/machines from the API...\n\r\n\r")

url = "https://api.security.microsoft.com/api/machines"

headers = { 
    'Content-Type' : 'application/json',
    'Accept' : 'application/json',
    'Authorization' : "Bearer " + aadToken
}

req = urllib.request.Request(url, headers=headers)
response = urllib.request.urlopen(req)

jsonResponse = json.loads(response.read())

machineresults = jsonResponse["value"]


## INSERT MACHINE DATA

print("Writing new hosts/machines to the database...\n\r\n\r")

print("Updating existing host/machine metadata in the database...\n\r\n\r")

for result in machineresults:
     sql = ''' INSERT OR IGNORE INTO Machines (id,computerDnsName,firstSeen,lastSeen,osPlatform,version,osProcessor,lastIpAddress,lastExternalIpAddress,osBuild,healthStatus,rbacGroupId,rbacGroupName,riskScore,exposureLevel,isAadJoined,aadDeviceId,InsertDatetime) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) '''
     data = (result["id"], result["computerDnsName"], result["firstSeen"], result["lastSeen"], result["osPlatform"], result["version"], result["osProcessor"], result["lastIpAddress"], result["lastExternalIpAddress"], result["osBuild"], result["healthStatus"], result["rbacGroupId"], result["rbacGroupName"], result["riskScore"], result["exposureLevel"], result["isAadJoined"], result["aadDeviceId"], current_epoch)
     cur.execute(sql, data)
     con.commit()

     cur.execute('''UPDATE Machines SET (computerDnsName,firstSeen,lastSeen,osPlatform,version,osProcessor,lastIpAddress,lastExternalIpAddress,osBuild,healthStatus,rbacGroupId,rbacGroupName,riskScore,exposureLevel,isAadJoined,aadDeviceId,LastUpdated) = (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) WHERE id = ?''', (result["computerDnsName"],result["firstSeen"],result["lastSeen"],result["osPlatform"],result["version"],result["osProcessor"],result["lastIpAddress"],result["lastExternalIpAddress"],result["osBuild"],result["healthStatus"],result["rbacGroupId"],result["rbacGroupName"],result["riskScore"],result["exposureLevel"],result["isAadJoined"],result["aadDeviceId"],current_epoch,result["id"],))
     con.commit()

print("Finished pulling and updating data!...\n\r\n\r")

#####################
# RETREIVE DATA
# NEW VULNERABILITIES SINCE LAST RUN
print("New Vulnerabilites Since Last Run\r\n")

t = PrettyTable(['CVE', 'Severity', 'CVSS', 'Vendor', 'Product', 'Version', 'Hostname', 'Exploit', 'EPSS', 'Last Seen'])

sql = "SELECT MIN(InsertDatetime) FROM (select InsertDatetime from VulnsByMachine GROUP BY InsertDatetime ORDER BY InsertDatetime DESC LIMIT 2)"
cur.execute(sql)
LastInsert = [row[0] for row in cur.fetchall()]
LastInsert = str(LastInsert[0])

for row in cur.execute("SELECT DISTINCT vbm.cveId,vbm.severity,vd.cvssV3,vbm.productVendor,vbm.productName,vbm.productVersion,m.computerDnsName,vd.publicExploit,vd.epss,datetime(vbm.InsertDatetime, 'unixepoch', 'localtime') AS LastSeen FROM VulnsByMachine vbm INNER JOIN Machines m on vbm.machineId = m.id INNER JOIN VulnDetails vd ON vd.id = vbm.cveId WHERE vbm.InsertDatetime > '" + LastInsert + "' ORDER BY vd.publicExploit DESC,vd.cvssV3 DESC"):
     t.add_row(row)
print(t)

t = PrettyTable(['Total New'])

for row in cur.execute("SELECT DISTINCT count(*) FROM VulnsByMachine vbm INNER JOIN Machines m on vbm.machineId = m.id INNER JOIN VulnDetails vd ON vd.id = vbm.cveId WHERE vbm.InsertDatetime > '" + LastInsert + "' ORDER BY vd.cvssV3 DESC"):
     t.add_row(row)
print(t)

# NUMBER OF VULNS NOT SEEN SINCE LAST RUN
print("\r\nNumber of Vulns Not Seen Since Last Run\r\n")

t = PrettyTable(['CVE', 'Severity', 'CVSS', 'Vendor', 'Product', 'Version', 'Hostname', 'Last Seen'])

sql = "SELECT MIN(LastUpdated) FROM (select LastUpdated from VulnsByMachine GROUP BY LastUpdated ORDER BY LastUpdated DESC LIMIT 2)"
cur.execute(sql)
LastRun = [row[0] for row in cur.fetchall()]
LastRun = str(LastRun[0])

for row in cur.execute("SELECT vbm.cveId,vbm.severity,vd.cvssV3,vbm.productVendor,vbm.productName,vbm.productVersion,m.computerDnsName,vbm.LastUpdated FROM VulnsByMachine vbm INNER JOIN Machines m ON m.id = vbm.machineId INNER JOIN VulnDetails vd ON vd.id = vbm.cveId WHERE vbm.LastUpdated = '" + LastRun + "' ORDER BY vd.cvssV3 DESC LIMIT 50"):
     t.add_row(row)
print(t)

t = PrettyTable(['Total Out'])

for row in cur.execute("SELECT count(*) FROM VulnsByMachine vbm INNER JOIN Machines m ON m.id = vbm.machineId INNER JOIN VulnDetails vd ON vd.id = vbm.cveId WHERE vbm.LastUpdated = '" + LastRun + "'"):
     t.add_row(row)
print(t)

# LONGEST PERIOD SINCE VULN WAS LAST SEEN
print("\r\nLongest Period Since Vuln Was Last Seen\r\n")

t = PrettyTable(['Last Seen'])

for row in cur.execute("select vd.updatedOn FROM VulnsByMachine vbm INNER JOIN Machines m ON vbm.machineId = m.id INNER JOIN VulnDetails vd ON vd.id = vbm.cveId ORDER BY vd.updatedOn ASC LIMIT 1"):
     t.add_row(row)
print(t)

# LONGEST PERIOD SINCE HOST WAS LAST SEEN
print("\r\nLongest Period Since Host Was Last Seen\r\n")

t = PrettyTable(['Last Seen'])

for row in cur.execute("select m.lastSeen FROM VulnsByMachine vbm INNER JOIN Machines m ON vbm.machineId = m.id INNER JOIN VulnDetails vd ON vd.id = vbm.cveId ORDER BY m.lastSeen ASC LIMIT 1"):
     t.add_row(row)
print(t)

# LAST TEN RUNS BY CVE COUNT
print("\r\nLast Ten Runs by CVE Count\r\n")

CritCnt = 0
HighCnt = 0
MedCnt = 0
LowCnt = 0

for row in cur.execute("SELECT severity,count(*) AS cnt FROM (SELECT vbm.severity FROM VulnsByMachine vbm INNER JOIN Machines m on vbm.machineId = m.id WHERE m.LastUpdated = '" + str(current_epoch) + "' GROUP BY severity,cveId) GROUP BY severity"):
     if row[0] == "Critical":
          CritCnt = int(row[1])
     if row[0] == "High":
          HighCnt = int(row[1])
     if row[0] == "Medium":
          MedCnt = int(row[1])
     if row[0] == "Low":
          LowCnt = int(row[1])

sql = ''' INSERT INTO PointInTimeCVECount (InsertDatetime,Critical,High,Medium,Low) VALUES(?, ?, ?, ?, ?) '''
data = (current_epoch,CritCnt,HighCnt,MedCnt,LowCnt)
cur.execute(sql, data)
con.commit()

t = PrettyTable(['Critical', 'High', 'Medium', 'Date'])

for row in cur.execute("select Critical,High,Medium,datetime(InsertDatetime, 'unixepoch', 'localtime') from PointInTimeCVECount order by InsertDatetime DESC LIMIT 10"):
     t.add_row(row)
print(t)

# LAST TEN RUNS BY TOTAL VULN COUNT
print("\r\nLast Ten Runs by Total Vuln Count\r\n")

sql = ''' INSERT INTO PointInTimeTotalVulnCount (InsertDatetime,Critical,High,Medium,Low) VALUES(?, ?, ?, ?, ?) '''
data = (current_epoch,CountBySeverity[1],CountBySeverity[3],CountBySeverity[5],0)
cur.execute(sql, data)
con.commit()

t = PrettyTable(['Critical', 'High', 'Medium', 'Date'])

for row in cur.execute("select Critical,High,Medium,datetime(InsertDatetime, 'unixepoch', 'localtime') from PointInTimeTotalVulnCount order by InsertDatetime DESC LIMIT 10"):
     t.add_row(row)
print(t)

con.close()