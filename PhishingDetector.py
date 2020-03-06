import pandas as pd
import numpy as np
from sklearn import model_selection
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
import re
from urllib.parse import urlsplit
from datetime import date
from datetime import datetime
import whois
import requests
from bs4 import BeautifulSoup
import socket
from tldextract import extract
import dns.resolver
import ssl

#Load dataset
names = ['having_IP_Address', 'URL_Length', 'Shortining_Service',
         'having_At_Symbol', 'double_slash_redirecting',
         'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_state',
         'Domain_registeration_length', 'Favicon', 'port',
         'HTTPS_token', 'Request_url', 'Links_in_tags',
         'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect', 
         'Iframe', 'age_of_domain', 
         'DNS_record', 'Statistical_report', 'Result']

#WORK ON:
#web traffic

#TRY TO ADD:
#Page Rank, Google index, links pointing to page

data = pd.read_csv("./TrainingSet.csv", header=None, names=names)


#Train Dataset

#Split data into training and test cases 80/20
array = data.values
X = array[1:,:22] #all values in each row except Result
Y = array[1:,22] #Result column
X_train, X_validation, Y_train, Y_validation = model_selection.train_test_split(X, Y, test_size=0.2)

#Train DCT Classifier
print("\nDecision Tree Classifier for Phishing Detector\n")
dct = DecisionTreeClassifier()
dct.fit(X_train, Y_train)
predictions = dct.predict(X_validation)
accuracy = accuracy_score(Y_validation, predictions) * 100.00
print("Accuracy of DCT model (%): ", accuracy, "\n")


#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#XX  ABOVE IS TRAINING MODEL // BELOW IS INPUTTING AND PREDICTING NEW DATA  XX
#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


#Function for finding IP Address
def find_ip(s):
    ip = re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s)
    if not ip:
        return 1 #if no ip found, return legit
    else:
        return -1

#Function for finding url length
def url_length(s):
    if (len(s) < 54):
        return 1
    elif (len(s) >= 54 and len(s) <= 75):
        return 0
    else:
        return -1

#Function for detecting shortening services through redirects ***MAY HAVE TO CHANGE TO REGEX***
def short_service(s):
    if 'http' not in s:
        s = 'http://' + s
    try:
        response = requests.get(s)
    #Website forcibly cancels connection, very suspicious
    except:
        print("\n\n***ERROR***\n")
        print("The connection to this url has been forcibly terminated by a remote host. It is highly recommended to not use the site or enter any information.")
        raise SystemExit
    code = response.status_code

    if (code == 302 or code == 301): #302 is response code for redirects
        return -1
    else:
        return 1

#Function for finding @ symbol
def find_at_symbol(s):
    if (s.find('@', 0, len(s) - 1) == -1): #if there is no @ symbol in the URL
        return 1
    else:
        return -1

#Function for detecting doduble slash redirecting
def dbl_slash_redirecting(s):
    if (s.rfind('//') > 7):
        return -1
    else:
        return 1

#Function for finding - symbol in domain
def prefix_suffix(s):
    tsd, td, tsu = extract(s) # prints www, hostname, com
    hostname = td
    if (hostname.find('-', 0, len(hostname) - 1) == -1): #if there is no dash
        return 1
    else:
        return -1

#Function for determining sub domains
def find_dots(s):
    count = 0
    for i in s:
        if i == '.':
            count = count + 1
    return count

def find_sub_domains(s):
    #extract url sub domains
    tsd, td, tsu = extract(s)

    #if there is just one dot, safe
    if find_dots(tsd) <= 1:
        return 1
    #if 2, suspiscous
    elif find_dots(tsd) == 2:
        return 0
    #if more, phishing
    else:
        return -1

#Function for SSL
def get_SSL(s):
    port = '443'
    hostname = s
    
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
    
                start = ssock.getpeercert().get('notBefore')
                exp = ssock.getpeercert().get('notAfter')
                
                date_start = datetime.strptime(start, '%b %d %X %Y %Z')
                date_exp = datetime.strptime(exp, '%b %d %X %Y %Z')
    
                if date_exp.year - date_start.year >= 1:
                    return 1
                else:
                    return 0
    #Catch error if certificate is invalid
    except:
        print("\n\nSSL_ERROR: CERTIFICATE_VERIFY_FAILED\nSSL certificate for this url is not valid.\n\n")
        return -1


#Function for Domain Registration Expiration
def get_registration_exp(s):
    domain = whois.whois(s)
    exp_date = domain.get('expiration_date')
    today = date.today()

    if exp_date == None:
        return -1
    else:
    #if exp date is less than a year away return -1 (MULTIPLE DATES)
        try:
            if ((exp_date[0].year - today.year == 1 and exp_date[0].month - today.month <= 0) or exp_date[0].year - today.year < 1):
                return -1
            else:
                return 1
            #(SINGLE DATE)
        except:
            if ((exp_date.year - today.year == 1 and exp_date.month - today.month <= 0) or exp_date.year - today.year < 1):
                return -1
            else:
                return 1

#Functions for detecting external favicon links
def get_favicon(s):
    if 'http' not in s:
        s = 'http://' + s
    page = requests.get(s)
    soup = BeautifulSoup(page.text, features="lxml")
    icon_link = soup.find("link", rel="shortcut icon")
    if icon_link is None:
        icon_link = soup.find("link", rel="icon")
    if icon_link is None:
        return s + '/favicon.ico'
    return icon_link["href"]

def favicon_domain(favicon, s):
    fav_domain = "{0.scheme}://{0.netloc}/".format(urlsplit(favicon))
    original_domain = "{0.scheme}://{0.netloc}/".format(urlsplit(s))

    if (fav_domain == original_domain): #if there is no external favicon link
        return 1
    else:
        return -1

#Function for detecting non-standard ports
def check_server(address, port):
	# Create a TCP socket
	s = socket.socket()
	print("Attempting to connect to %s on port %s" % (address, port))
	try:
		s.connect((address, port))
		print("Connected to %s on port %s" % (address, port))
		return True
	except socket.error:
		print("Connection to %s on port %s failed" % (address, port))
		return False

def check_port(s):
    #Remove http token
    if s.find("http://") != -1:#if url has http token
        s_new = s.replace("http://", "")
    elif s.find("https://") != -1:
        s_new = s.replace("https://", "")
    else:
        s_new = s
            
    if (check_server(s_new, 21) == False and check_server(s_new, 22) == False and check_server(s_new, 23) == False and check_server(s_new, 80) == True and check_server(s_new, 443) == True and check_server(s_new, 445) == False and check_server(s_new, 1433) == False and check_server(s_new, 1521) == False and check_server(s_new, 3306) == False and check_server(s_new, 3389) == False):
        return 1
    else:
        return -1
    
#Function for detecting HTTP token within domain
def HTTP_token(s):
    tsd, td, tsu = extract(s) # prints www, hostname, com
    hostname = td
    if hostname.find("http") == -1 and hostname.find("https") == -1: #if no token found in domain
        return 1
    else:
        return -1

#Function for extracting all links and calculating percentage of abnormal ones
def request_url(s):
    if 'http' not in s:
        s = 'http://' + s
    html_page = requests.get(s)
    soup = BeautifulSoup(html_page.text, features="lxml")
    
    #array and loop to hold links from html soup file
    links = []
    
    for link in soup.findAll(attrs={'href': re.compile("http")}):
        links.append(link.get('href'))
    
    tsd, td, tsu = extract(s)
    hostname = td
    abnormal = 0 #abnormal external links
    total = 0 #total links in file
    for i in links:
        s = s.replace("http://", "") #remove http token
        if i.find(hostname) == -1: #if link does not contain original domain
            abnormal = abnormal + 1
            total = total + 1
        else:
            total = total + 1
    
    #calculate percentage of abnormal links
    if total > 0:
        percent = int((abnormal / total) * 100)
    else:
        percent = 0
    
    if percent < 22:
        return 1
    elif percent >= 22 and percent < 61:
        return 0
    else:
        return -1
    
#Function for finding percentage of external links in certain html tags
def links_in_tags(s):
    if 'http' not in s:
        s = 'http://' + s
    r = requests.get(s).content
    soup = BeautifulSoup(r, 'lxml')
    scripts = [item['src'] for item in soup.select('script[src]')]
    metas = [item['src'] for item in soup.select('meta[src]')]
    links = [item['src'] for item in soup.select('link[src]')]
    
    #if there are 2 or less external links, ignore
    if len(scripts) + len(metas) + len(links) <= 1:
        return 1
    else:
        tsd, td, tsu = extract(s)
        hostname = td
        #calculate percentage of abnormal domains
        total = len(scripts) + len(metas) + len(links)
        abnormal = 0
        
        #loops to find abnormal links
        for i in scripts:
            if i.find(hostname) == -1:
                abnormal = abnormal + 1
        
        for i in metas:
            if i.find(hostname) == -1:
                abnormal = abnormal + 1
                
        for i in links:
            if i.find(hostname) == -1:
                abnormal = abnormal + 1

        percent = (abnormal / total) * 100

        if percent < 17:
            return 1
        elif percent >= 17 and percent <= 81:
            return 0
        else: 
            return -1
    
#Function for detecting Server from Handler
def get_SFH(s):
    if 'http' not in s:
        s = 'http://' + s
    html_page = requests.get(s)
    soup = BeautifulSoup(html_page.text, features="lxml")
    
    blankSFH = soup.findAll('form', attrs={'action' : 'about:blank'})
    emptySFH = soup.findAll('form', attrs={'action' : ''})
    phish = len(blankSFH) + len(emptySFH)
    #if SFH is blank or null return phishing
    if phish > 0:
        return -1
    
    tsd, td, tsu = extract(s)
    hostname = td
    regex = r"^" + re.escape(hostname)
    
    SFH = soup.findAll('form', attrs={'action' : re.compile('.')})
    externalSFH = soup.findAll('form', attrs={'action' : re.compile(regex)})
    #if no handler is found  or returns an external domain, return suspicious
    if len(SFH) == 0 or len(externalSFH) > 0:
        return 0
    else:
        return 1

#Function for email submitions
def submit_email(s):  
    ids = 'MX'    #id for mailing server
        
    try:
        answers = dns.resolver.query(s, ids)
        for rdata in answers:
            if rdata.to_text().find('mail') != -1: #if mail function is found
                return -1
            else:
                return 1
    except Exception:
        return -1
    
#Function for detecting abnormal domain names in whois
def abnormal_url(s):
    tsd, td, tsu = extract(s) # prints www, hostname, com
    hostname = td + "." + tsu
    upperHN = hostname.upper()
    
    who = whois.whois(s)
    domain = who.get('domain_name')[0]
    
    if domain == hostname or domain == upperHN: #if domain is found in whois
        return 1
    else:
        return -1

#Function for detecting number of redirects
def redirects(s):
    if 'http' not in s:
        s = 'http://' + s
    r = requests.get(s) 
    redirectHistory = len(r.history)
    if redirectHistory <= 1: #if there are 0 or 1 redirects
        return 1
    elif redirectHistory >= 2 or redirectHistory < 4:
        return 0
    else:
        return -1

#Function for detecting right click disabling
def rightclick_disabling(s):
    if 'http' not in s:
        s = 'http://' + s
    page = requests.get(s)
    soup = BeautifulSoup(page.text, features="lxml")
    events = ["event.button == 2", "event.button==2", "event.button ==2", "event.button== 2"] #JS function which disables rightclick function
    rightclick = any(x in soup for x in events)
    
    if rightclick: #if rightclick is disabled
        return -1
    else:
        return 1

#Function for detecting pop ups with input fields
def popups(s):
    if 'http' not in s:
        s = 'http://' + s
    page = requests.get(s)
    soup = BeautifulSoup(page.text, features="lxml")
    prompt = ["prompt"]
    popUp = any(x in soup for x in prompt)

    if popUp: #if popUp contains input fields
        return -1
    else:
        return 1
   
#Function for detecting Iframe
def iframe(s):
    if 'http' not in s:
        s = 'http://' + s
    page = requests.get(s)
    soup = BeautifulSoup(page.text, features="lxml")
    attr = ["frameborder = \"0\"", "frameborder=\"0\"", "frameborder =\"0\"", "frameborder= \"0\"",
              "frameBorder = \"0\"", "frameBorder=\"0\"", "frameBorder =\"0\"", "frameBorder= \"0\""]
    frameborder = any(x in soup for x in attr)

    if frameborder: #if frameborder attribute is 0 (no broder)
        return -1
    else:
        return 1
    
#Function for getting domain age
def domain_age(s):
    domain = whois.whois(s)
    cre_date = domain.get('creation_date')
    today = date.today()

    if cre_date == None:
        return -1
    else:
        try:
            #if domain is a year old or older OR if domain is more than 6 months old
            if (today.year - cre_date.year >= 1) or (today.month - cre_date.month >= 6):
                return 1
            else:
                return -1
        #MULTIPLE DATES
        except:
            if (today.year - cre_date[0].year >= 1) or (today.month - cre_date[0].month >= 6):
                return 1
            else:
                return -1

#Function getting DNS Record
def get_records(s):
    #Top 10 DNS record ids
    ids = [
        'A',
        'NS',   
        'CNAME',
        'SOA',
        'PTR',
        'MX',
        'TXT',
        'AAAA',
        'SRV',
        'CERT',
    ]
    
    records = []
    for a in ids:
        try:
            answers = dns.resolver.query(s, a)
            for rdata in answers:
                records.append(rdata.to_text())
                print(a, ':', rdata.to_text())
                
        except Exception:
            pass
    
    #if no record is found
    if len(records) == 0 or len(records) == None:
        return -1
    else:
        return 1
    
#Function for getting web rank from alexa database
def web_traffic(s):
    html_page = requests.get("http://alexa.com/siteinfo/" + s)
    soup = BeautifulSoup(html_page.text, features="lxml")
    
    try:
        rank = soup.findAll('div', attrs={'class' : 'rankmini-rank'})
        
        span = "span>"
        regex = span + "\d+"
        OHT = "10000"
        highRegex = span + OHT + "[1-9]+"
        if rank[0].find(re.compile(regex)) == -1: #if no rank is found
            return -1
        elif rank[0].find(re.compile(highRegex)) != -1: #if rank is over 100,000
            return 0
        else:
            return 1
    except:
        print("This site has no information in the Alexa Database.")
        return -1
    
#Function for getting statistical report of top 10 phishing sites
def stat_report(s):
    url = "https://www.phishtank.com/stats/2013/01/"
    r = requests.get(url)  
    c = r.content
    
    soup = BeautifulSoup(c, features="lxml")    
    table = soup.find_all("table", attrs = {"class":"data"})
    
    domains = re.findall("[a-zA-Z0-9]*\.[a-zA-Z]{2,3}", table[2].text)
    
    for x in domains:
        if x == s:    #if given url is listed in top 10 phishing urls
            return -1
        
    return 1

#Inputting new data and making real-time predictions
newNames = ['having_IP_Address', 'URL_Length', 'Shortining_Service',
         'having_At_Symbol', 'double_slash_redirecting',
         'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_state',
         'Domain_registeration_length', 'Favicon', 'port',
         'HTTPS_token', 'Request_url', 'Links_in_tags',
         'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect', 
         'Iframe', 'age_of_domain', 
         'DNS_record', 'Statistical_report']

newData = pd.read_csv("./NewData.csv", header=None, names=newNames)

#Input URL
URL = input("Enter URL: ")

#Determine values of each attribute for inputted URL
#Having IP Address
having_IP_Address = find_ip(URL)

#URL Length
URL_Length = url_length(URL)

#Shortening Service
Shortining_Service = short_service(URL)

#Having @ symbol
having_At_Symbol = find_at_symbol(URL)

#Double Slash Redirecting
double_slash_redirecting = dbl_slash_redirecting(URL)

#Prefix/Suffix
Prefix_Suffix = prefix_suffix(URL)

#Having Sub Domain
having_Sub_Domain = find_sub_domains(URL)

#SSL
SSLfinal_state = get_SSL(URL)

#Domain Registration Length
Domain_registration_length = get_registration_exp(URL)

#Favicon domain
Favicon = favicon_domain(get_favicon(URL), URL)

#Port
port = check_port(URL)

#HTTPS Token
HTTPS_token = HTTP_token(URL)

#Request URL
Request_url = request_url(URL)

#Links in tags
Links_in_tags = links_in_tags(URL)

#SFH
SFH = get_SFH(URL)

#Submit Email
Submitting_to_email = submit_email(URL)
#Abnormal URL
Abnormal_URL = abnormal_url(URL)

#Redirect
Redirect = redirects(URL)

#Right Click
RightClick = rightclick_disabling(URL)

#Pop Up Window
popUpWindow = popups(URL)

#Iframe
Iframe = iframe(URL)

#Age of Domain
age_of_domain = domain_age(URL)

#DNS Record
DNS_record = get_records(URL)

#Web Traffic
#Web_traffic = web_traffic(URL)

#Statistical Report
Statistical_report = stat_report(URL)

newInput = [having_IP_Address, URL_Length, Shortining_Service,
         having_At_Symbol, double_slash_redirecting,
         Prefix_Suffix, having_Sub_Domain, SSLfinal_state,
         Domain_registration_length, Favicon, port,
         HTTPS_token, Request_url, Links_in_tags,
         SFH, Submitting_to_email, Abnormal_URL, Redirect, 
         Iframe, age_of_domain, 
         DNS_record, Statistical_report]
 
#Predict results using trained model and new features
newArray = np.asarray(newInput)
result = dct.predict(newArray.reshape(1, -1))

#FINAL RESULT
print("\n")
print("URL (" + URL + ") has been analyzed.")
if (result == '-1'):
    print("This website is phishing.\nDo not enter any information and exit immediately.")
elif (result == '0'):
    print("This website may be safe, but is suspicious.\nUse caution.")
elif (result == '1'):
    print("This website is safe!")
else:
    print("Error.")