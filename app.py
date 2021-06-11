#!/bin/bash
from flask import Flask
from nslookup import Nslookup
from datetime import datetime
from collections import defaultdict
from scapy.layers.inet import traceroute
from bs4 import BeautifulSoup
from phonenumbers import carrier,timezone,geocoder
from cymruwhois import Client
from shodan import Shodan
from threading import Thread
from pymongo import MongoClient

import socket
import sublist3r
import requests
import nmap3
import whois
import phonenumbers
import copy
import re
import json


class COMMON:# Common function for all classes
    def __init__(self):
        self.errordomain=list()

    def error(self, code):# Error handler
        try:return eval(code)
        except:open("Targets/error.log", "a").write(code + "\n")

    def handle(self, var, val):
        try:return eval(val)
        except:return None 

    def httpprobe(self,d):
        try:
            requests.get(f'https://{d}')
            return f'https://{d}'
        except:
            try:
                requests.get(f'http://{d}')
                return f'http://{d}'
            except:self.errordomain.append(d)

    def myconverter(self,o):
        if isinstance(o, datetime):return o.strftime('%D:%H:%M:%S')


class INFOSPLOIT: # Fully manual mode info collector of given link
    def __init__(self,url,key):
        self.cm=COMMON()
        self.key=key
        if self.key != None:self.process=[self.DNS,self.SUBDOMAIN,self.WHOIS,self.NMAP,self.URL,self.SHODAN]
        else:self.process=[self.DNS,self.SUBDOMAIN,self.WHOIS,self.NMAP,self.URL]
        self.hlp={'IPv6':'AAAA','Name Server':'NS','Mail Exchangers':'MX','Start of Authority':'SOA','Text':'TXT'}
        for rp in re.findall(r'^https?://',url):url=url.replace(rp,"")
        self.url=self.cm.httpprobe(url)
        self.domain='.'.join(self.url.split("://")[-1].split("/")[0].split('.')[-2:])
        self.rslt={'IPv4':socket.gethostbyname(self.domain),'IPv6':list(),'Name Server':list(),'Mail Exchangers':list(),'Start of Authority':list(),'Text':list(),'Subdomains':list()}
        self.Start()

    def Start(self):
        thread=[]
        for p in self.process:
            new=Thread(target=p)
            new.start()
            thread.append(new)
        for t in thread:
            while t.is_alive():pass
        self.rslt['Error Domains']=self.cm.errordomain
        # open('test.json','w').write(json.dumps(self.rslt,indent=4))
        self.view()

    def DNS(self): # Domain Infomation manual
        dns=Nslookup(dns_servers=['1.1.1.1','8.8.8.8','8.8.0.0'])
        for k,v in self.hlp.items():
            record=dns.base_lookup(self.domain,v)
            self.rslt[k]=[str(r) for r in record.rrset]
        self.rslt['Domain']=self.domain
        self.rslt['Canonical Name']=str(record.canonical_name)
        self.rslt['Top level domain']=self.domain.split('.')[-1]
        self.rslt['Secondary level domain']=self.domain.split('.')[-2]
        self.rslt['Routes']=[f'{snd.ttl} {rcv.src}' for snd, rcv in traceroute(self.rslt['IPv4'], maxttl=10,verbose=False)[0]]

    def SUBDOMAIN(self): # Bruteforce
        for d in list(set(sublist3r.main(self.domain, 0, None, ports= None, silent=False, verbose=False, enable_bruteforce= False, engines=None))):self.rslt['Subdomains'].append(self.cm.httpprobe(d))

    def WHOIS(self): # Domain details gether from whois and other
        ct=Client().lookup(self.rslt['IPv4']).__dict__
        self.rslt['ASN']=ct['asn']
        self.rslt['Range']=ct['prefix']
        self.rslt['Owner']=ct['owner']
        dt=whois.whois(self.domain)
        self.rslt['Registrar']=dt['registrar']
        self.rslt['Emails']=dt['emails']
        self.rslt['Name']=dt['name']
        self.rslt['Organization']=dt['org']
        self.rslt['Address']=dt['address']
        self.rslt['City']=dt['city']
        self.rslt['Country']=dt['country']
        self.rslt['State']=dt['state']
        self.rslt['Zipcode']=dt['zipcode']
        self.rslt['Creation Date']=[i.strftime('%D:%H:%M:%S') for i in dt['creation_date']]
        self.rslt['Updated Date']=[i.strftime('%D:%H:%M:%S') for i in dt['updated_date']]
        self.rslt['Expiration Date']=[i.strftime('%D:%H:%M:%S') for i in dt['expiration_date']]
        self.rslt['Status']=dt['status']
        self.rslt['Referral url']=dt['referral_url']

    def NMAP(self): # Edit here only valuable information gather from the nmap result
        self.rslt['Ports']=list()
        for p in nmap3.NmapScanTechniques().nmap_tcp_scan(self.rslt['IPv4'],args='-sV')[self.rslt['IPv4']]['ports']:
            service='{} {}'.format(self.cm.handle(p,"var['service']['product']"),self.cm.handle(p,"var['service']['version']")).replace("None", "").strip()
            self.rslt['Ports'].append({'Port':p['portid'],'Name':p['service']['name'],'Service':service,'Protocol':p['protocol'],'Exploits Suggestions':self.search(service)})

    def URL(self):
        r=requests.get(self.url)
        soup=BeautifulSoup(r.content,'html5lib')
        self.rslt['URL']=defaultdict(list)
        self.rslt['URL']['Response Headers']=dict(r.headers)
        self.rslt['URL']['Render']=str(r.content)
        self.rslt['URL']['Contacts'],self.rslt['Mails']=self.contact(r.content.decode())
        for a in soup.findAll('a',href=True):
            if re.findall(r'^http',a['href']):self.rslt['URL']['Links'].append(a['href'])
            else:self.rslt['URL']['Links'].append(f"{self.url}{a['href']}")
        for img in soup.findAll('img'):
            if img.get('src'):
                if re.findall(r'^http',str(img.get('src'))):self.rslt['URL']['Images'].append({img.get("alt"):img.get("src")})
                else:self.rslt['URL']['Images'].append({img.get("alt"):f'{self.url}{img.get("src")}'})
        for s in soup.findAll('script'):
            if s.get('src'):
                if re.findall(r'^http',str(s.get('src'))):self.rslt['URL']['Javascript'].append(s.get('src'))
                else:self.rslt['URL']['Javascript'].append(f'{self.url}{s.get("src")}')
        for inpt in soup.findAll('input'):self.rslt['URL']['Inputs'].append({inpt.get('name'):[inpt.get('type'),inpt.get('onclick')]})
        self.rslt['URL']['Robots']=requests.get(f'{self.url}/robots.txt').content.decode()
        self.rslt['URL']['Sitemap']=requests.get(f'{self.url}/sitemap.xml').content.decode()

    def SHODAN(self):
        tmp=defaultdict(dict)
        rm=['_shodan', 'hash', 'os', 'timestamp', 'tags', 'ip', 'isp', 'location', 'port','product','version', 'vulns', 'hostnames', 'transport', 'domains', 'org', '_id', 'asn', 'cloud', 'ip_str']
        st=Shodan(self.key).host(self.rslt['IPv4'])
        tmp['Area code']=st['area_code']
        tmp['ASN']=st['asn']
        tmp['City']=st['city']
        tmp['Country Code']=st['country_code']
        tmp['Country Name']=st['country_name']
        tmp['DMA COde']=st['dma_code']
        tmp['Domains']=st['domains']
        tmp['Hostnames']=st['hostnames']
        tmp['IP']=st['ip']
        tmp['IP String']=st['ip_str']
        tmp['Internet Service Provider']=st['isp']
        tmp['Last Update']=st['last_update']
        tmp['Latitude Longitude']='{} {}'.format(st['latitude'],st['longitude'])
        tmp['Oragnization']=st['org']
        tmp['Operating System']=st['os']
        tmp['Postal Code']=st['postal_code']
        tmp['Region Code']=st['region_code']
        tmp['Tags']=st['tags']
        for p in st['data']:
            temp=copy.copy(p)
            for k in rm:
                try:temp.pop(k)
                except:pass
            tmp['Ports'][p['port']]={'Data':temp,'Port':self.cm.handle(p,"var['port']"),'Transport':self.cm.handle(p,"var['transport']"),'Product':self.cm.handle(p,"var['product']"),'Version':self.cm.handle(p,"var['version']"),'Vulns':self.cm.handle(p,"var['vulns']")}
        self.rslt['Shodan']=tmp

    def contact(self, res):  # Contact information extractor from the websites
        c = []
        for mob in [match.number for match in phonenumbers.PhoneNumberMatcher(res, "IN")]:
            x = phonenumbers.parse("+{}{}".format(mob.country_code, mob.national_number), None)
            c.append({"number": str(x.country_code) + str(x.national_number),"name": carrier.name_for_number(x, "en"),"timezone": timezone.time_zones_for_number(x)[0],"country": geocoder.description_for_number(x, "en"),})
        return c, list(set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.com", res)))

    def search(self, query): # Exploits search from exploits-db.com
        edb = defaultdict(dict)
        if query != "":
            for link in BeautifulSoup(requests.get("https://www.google.com/search?q=" + query + "+site:exploit-db.com").content,"html5lib").findAll("div", {"class": "ZINbbc xpd O9g5cc uUPGi"}):
                for l in link.findAll("a", href=re.compile(r"https://www.exploit-db.com/exploits/[0-9]")):
                    text = link.find("div", {"class": "BNeawe s3v9rd AP7Wnd"}).getText()
                    lk = re.findall(r"https://www.exploit-db.com/exploits/[0-9]+", l["href"])[0]
                    id = lk.split("/")[-1]
                    edb[id]["link"] = lk
                    try:
                        edb[id]["cve"] = re.findall(r"CVE ?- ?\d{4} ?- ?\d{0,6}", text)[0]
                        text = text.replace(edb[id]["cve"], "")
                    except:edb[id]["cve"] = None
                    try:
                        edb[id]["date"] = re.findall(r"(\d{1,4} ?- ?\w{0,3}\d{0,2}? ?- ?\d{1,4})", text)[0]
                        text = text.replace(edb[id]["date"], "")
                    except:edb[id]["date"] = None
                    edb[id]["description"] = text.strip()
        return edb

    def dirbus(self,url): # directory bruteforce not used
        for word in self.dir:
            if requests.get(f'https://{url}/{word}',timeout=1).status_code == 200: self.rslt['URL']['Directories'].append(f'https://{url}/{word}')

    def view(self):
        style='''
            :root {
                --size: 5rem;
                --mcolor: #4edb39;
                --mpcolor: #4edb3950;
                --icolor: #4edb3990;
                --mocolor: #4edb3908;
            }
            body {
                background: black;
                color: snow;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
            }
            * {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                transition: all 0.5s;
                margin: auto;
                color: snow;
            }
            h4{
                width: 100%;
                text-align: center;
                cursor:pointer;
            }
            .infopanel {
                width: 100%;
                display: flex;
                flex-direction: column;
                justify-content: center;
            }
            .infoanim{
                position:absolute;
                display:flex;
                bottom: 4rem;
            }

            .infobox{
                overflow:auto;
                border-radius:0.3rem;
                box-shadow: 0px 0px 0.5rem 0px #4edb3950 inset;
                background:var(--mocolor);
            }
            table {
                display: none;
                border: none;
                width: 100%;
                margin:0rem;
                transition: all 0.5s;
            }
            td,th {
                text-align: left;
                border: 1px solid #4edb3950;
                border-radius: 0.3rem;
                width: fit-content;
                padding:0.5rem;
            }
            li{
                padding:0.5rem;
            }
            .arrow {
                border: solid var(--mcolor);
                border-width: 0 3px 3px 0;
                display: inline-block;
                padding: 3px;
                position: sticky;
                left: 98%;
                transform: rotate(-45deg);
            }
            .arrowbox{
                border: solid var(--mcolor);
                border-width: 0 3px 3px 0;
                display: inline-block;
                padding: 3px;
                position:relative;
                transform: rotate(-45deg);
                left:0.5rem;
                cursor: pointer;
                z-index: 10;
            }
            ::-webkit-scrollbar{
                width:0.2rem;
                height:0.2rem;
            }
            ::-webkit-scrollbar-track{
                background:none;
            }
            ::-webkit-scrollbar-thumb{
                background:#4edb3950;
                border-radius:0.3rem;
            }
        '''
        script='''
        $(document).ready(function () {
            $('h4').on("click", function (e) {
                if (this.nextElementSibling.style.display == "flex"){
                    this.childNodes[1].style.transform="rotate(-45deg)";
                    this.nextElementSibling.style.display="none";
                }else{
                    this.childNodes[1].style.transform="rotate(45deg)";
                    this.nextElementSibling.style.display="flex";
                }
                e.stopPropagation();
                e.preventDefault();
            });
        });
        '''
        self.URL=self.rslt.pop('URL')
        self.rtemplate=self.URL.pop('Render')
        self.SHODAND=self.rslt.pop('Shodan')
        self.f=0
        first=self.template(self.rslt[list(self.rslt.keys())[0]],self.rslt)
        self.f=0
        second=self.template(self.URL[list(self.URL.keys())[0]],self.URL)
        self.f=0
        third=self.template(self.SHODAND[list(self.SHODAND.keys())[0]],self.SHODAND)
        self.html=f'<h3>Server information</h3><div class="infobox">{first}</div><h3>URL information</h3><div class="infobox">{second}</div><h3>Shodan information</h3><div class="infobox">{third}</div>'
        # open('static/{self.domain}.{cur}.html','w').write(f'<html><head><title>ISPLOIT</title><style>{style}</style><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script></head><body><h1>ISPLOIT</h1>{t}<script>{script}</script></body></html>')
    
    def template(self,h,d):
        if self.f==1:cont=f'<div class="infopanel"><h4>{h}<i class="arrow"></i></h4><table>'
        else:cont=f'<div class="infopanel"><table style="display:block;">'
        self.f=1
        for k in d.keys():
            if type(d[k]) is str:
                if self.cm.handle(d[k],"re.findall(r'^https?.*',var)"):cont+=f'<tr><th>{k}</th><td><a href="{d[k]}" target="_blank">{d[k]}</a></td></tr>'
                else:cont+=f'<tr><th>{k}</th><td>{d[k]}</td></tr>'
            elif type(d[k]) is list:
                cont+=f'<tr><th>{k}</th><td>'
                for l in d[k]:
                    if self.cm.handle(l,"re.findall(r'^https?.*',var)"):cont+=f'<li><a href="{l}" target="_blank">{l}</a></li>'
                    elif type(l) is dict and k not in ["Contacts","Images","Inputs"]:cont+=f'<tr><td colspan="2">{self.template(l[list(l.keys())[0]],l)}</td></tr>'
                    else:cont+=f'<li>{l}</li>'
                cont+='</td></tr>'
            elif type(d[k]) is dict:
                if k != 'data':cont+=f'<tr><td colspan="2">{self.template(k,d[k])}</td></tr>'
        cont+='</table></div>'
        return cont
        
app=Flask(__name__)
app.secret_key = "&^$^*InfoSploit82738"
db=MongoClient('mongodb+srv://siva:(#*HELPMEBRO*#)@cluster0.yudpn.mongodb.net/ISPLOIT?retryWrites=true&w=majority').isploit

def apicall(domain,cur):
    api=INFOSPLOIT(domain,'QgvtKV5ePkrxZh3KCUhvI4RAEYhBdYsZ')
    db.domains.insert_one({'domain':'nmap.com','json':api.rslt,'html':api.html,'timestamp':cur})
    return api.html

# Speed up process now take 1 min to complete result
@app.route('/<request>')
def isploi(request):
    domain='.'.join(request.split("://")[-1].split("/")[0].split('.')[-2:])
    apidb=[i for i in db.domains.find({'domain':domain})]
    cur=datetime.now().strftime('%m')
    if not apidb:return apicall(domain,cur)
    else:
        if apidb['timestamp'] < cur:return apicall(domain,cur)
        else:return apidb['html']

if __name__=="__main__":
    app.run(debug=True)