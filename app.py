#!/bin/bash
from flask import Flask,redirect,url_for
from flask.globals import request
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
        if self.key != 'none':self.process=[self.DNS,self.SUBDOMAIN,self.WHOIS,self.NMAP,self.URL,self.SHODAN]
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
        # open(f'{self.domain}.json','w').write(json.dumps(self.rslt,indent=4))
        self.view()

    def DNS(self): # Domain Infomation manual
        dns=Nslookup(dns_servers=['1.1.1.1','8.8.8.8','8.8.0.0'])
        for k,v in self.hlp.items():
            record=dns.base_lookup(self.domain,v)
            self.rslt[k]=self.cm.handle(record,"[str(r) for r in var.rrset]")
        self.rslt['Domain']=self.domain
        self.rslt['Canonical Name']=self.cm.handle(record,"str(var.canonical_name)")
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
        try:self.rslt['Creation Date']=[i.strftime('%D:%H:%M:%S') for i in dt['creation_date']]
        except:self.rslt['Creation Date']=dt['creation_date']
        try:self.rslt['Updated Date']=[i.strftime('%D:%H:%M:%S') for i in dt['updated_date']]
        except:self.rslt['Updated Date']=dt['updated_date']
        try:self.rslt['Expiration Date']=[i.strftime('%D:%H:%M:%S') for i in dt['expiration_date']]
        except:dt['expiration_date']
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
                border: solid 1px var(--mcolor);
                border-radius: 0.2rem;
                width: fit-content;
                padding: 0.5rem;
                float: left;
                margin: 0.3rem;
                list-style-type: none;
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
        temp=copy.copy(self.rslt)
        self.URL=temp.pop('URL')
        self.rtemplate=self.URL.pop('Render')
        self.SHODAND=temp.pop('Shodan')
        self.f=0
        first=self.template(temp[list(temp.keys())[0]],temp)
        self.f=0
        second=self.template(self.URL[list(self.URL.keys())[0]],self.URL)
        self.f=0
        third=self.template(self.SHODAND[list(self.SHODAND.keys())[0]],self.SHODAND)
        t=f'<h3>Server information</h3><div class="infobox">{first}</div><h3>URL information</h3><div class="infobox">{second}</div><h3>Shodan information</h3><div class="infobox">{third}</div>'
        self.html=f'<html><head><title>ISPLOIT</title><link rel="icon" type="image/ico" href="static/isploit.ico"/><style>{style}</style><script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script></head><body style="background: black;"><svg xmlns="http://www.w3.org/2000/svg" x="0px" y="0px" width="96" height="96" viewBox="0 0 172 172" style=" fill:#000000;"><g fill="none" fill-rule="nonzero" stroke="none" stroke-width="1" stroke-linecap="butt" stroke-linejoin="miter" stroke-miterlimit="10" stroke-dasharray="" stroke-dashoffset="0" font-family="none" font-weight="none" font-size="none" text-anchor="none" style="mix-blend-mode: normal"><path d="M0,172v-172h172v172z" fill="none"></path><g fill="#4ddc39"><path d="M86,3.44c-29.50875,0 -54.62344,14.41844 -64.3925,34.64188c-0.57781,-0.12094 -1.14219,-0.24188 -1.65281,-0.24188c-5.30781,0 -9.63469,4.52844 -9.63469,10.07813c0,1.53187 0.34938,3.05031 0.99438,4.42094c-0.645,1.37062 -0.99438,2.87562 -0.99438,4.42094c0,1.54531 0.34938,3.05031 0.99438,4.42094c-0.645,1.37063 -0.99438,2.87563 -0.99438,4.42094c0,4.70312 3.10406,8.62687 7.26969,9.74219c-0.24187,1.22281 -0.38969,2.48594 -0.38969,3.77594c0,6.11406 2.795,11.58313 7.24281,15.3725c0.7525,0.63156 2.31125,3.27875 3.44,5.60344c-0.22844,0.99438 -0.36281,2.00219 -0.36281,2.99656c0,4.515 1.76031,9.11063 4.55531,12.99406c5.65719,19.80687 13.57187,25.53125 17.71062,28.39344c5.52281,3.81625 10.87094,5.32125 10.87094,10.32c0,5.67063 9.05687,10.32 15.02312,10.32h20.64c5.97969,0 15.02313,-4.64937 15.02313,-10.32c0,-4.99875 5.34812,-6.50375 10.87094,-10.32c4.13875,-2.86219 12.05344,-8.58656 17.69719,-28.38c2.80844,-3.88344 4.56875,-8.47906 4.56875,-13.0075c0,-0.99437 -0.13437,-1.98875 -0.37625,-2.99656c1.14219,-2.32469 2.70094,-4.97187 3.45344,-5.60344c4.44781,-3.78937 7.24281,-9.25844 7.24281,-15.3725c0,-1.29 -0.14781,-2.55312 -0.38969,-3.77594c4.16562,-1.11531 7.26969,-5.03906 7.26969,-9.74219c0,-1.53188 -0.34937,-3.05031 -0.99437,-4.42094c0.645,-1.37062 0.99437,-2.87562 0.99437,-4.42094c0,-1.54531 -0.34937,-3.05031 -0.99437,-4.42094c0.645,-1.37063 0.99437,-2.87563 0.99437,-4.42094c0,-5.54969 -4.32687,-10.07813 -9.63469,-10.07813c-0.51063,0 -1.075,0.12094 -1.65281,0.24188c-9.76906,-20.22344 -34.88375,-34.64188 -64.3925,-34.64188zM86,10.32c26.64656,0 49.35594,12.71188 58.06344,30.46281c-0.90031,0.49719 -1.8275,1.02125 -2.84875,1.62594c-0.41656,0.25531 -0.73906,0.45688 -0.71219,0.45688c-3.78937,1.43781 -6.3425,5.25406 -6.3425,9.47344c0,1.54531 0.34938,3.05031 0.99438,4.42094c-0.645,1.37063 -0.99438,2.87563 -0.99438,4.42094c0,4.23281 2.55313,8.04906 6.11406,9.37938c0.17469,0.09406 0.51062,0.28219 0.94062,0.55094c2.15,1.27656 4.00438,2.29781 5.68406,3.07719c0.65844,1.58563 1.02125,3.23844 1.02125,4.93156c0,3.88344 -1.70656,7.48469 -4.82406,10.11844c-0.84656,0.73906 -1.8275,2.09625 -2.795,3.62813c-3.30562,-3.9775 -8.14312,-6.86656 -13.02094,-6.86656c4.39406,2.365 6.88,5.32125 6.88,8.4925c0,6.65156 -5.38844,12.04 -12.04,12.04c-5.22719,0 -14.06906,-13.57187 -20.50562,-13.6525c-1.55875,2.12313 -4.07156,3.52063 -6.90688,3.52063c-0.47031,0 -1.49156,0.34937 -1.72,0.61812c-0.51062,1.80063 -3.74906,2.70094 -6.9875,2.70094c-3.225,0 -6.46344,-0.90031 -6.97406,-2.70094c-0.22844,-0.26875 -1.24969,-0.61812 -1.72,-0.61812c-2.84875,0 -5.34812,-1.3975 -6.90687,-3.52063c-6.45,0.08063 -15.29188,13.6525 -20.51906,13.6525c-6.63812,0 -12.04,-5.38844 -12.04,-12.04c0,-3.17125 3.29219,-6.43656 6.88,-8.4925c-5.01219,0 -9.79594,2.86219 -13.06125,6.81281c-0.95406,-1.505 -1.90812,-2.84875 -2.76812,-3.57438c-3.10406,-2.63375 -4.81063,-6.235 -4.81063,-10.11844c0,-1.69312 0.36281,-3.34594 1.02125,-4.93156c1.66625,-0.77937 3.52063,-1.80062 5.67063,-3.07719c0.44344,-0.26875 0.73906,-0.47031 0.71219,-0.44344c3.80281,-1.45125 6.35594,-5.25406 6.35594,-9.48688c0,-1.54531 -0.34937,-3.05031 -0.99437,-4.42094c0.645,-1.37062 0.99437,-2.87562 0.99437,-4.42094c0,-4.23281 -2.55312,-8.03563 -6.10062,-9.36594c-0.18813,-0.09406 -0.52406,-0.29563 -0.95406,-0.56438c-1.02125,-0.60469 -1.94844,-1.12875 -2.84875,-1.62594c8.7075,-17.75094 31.41687,-30.46281 58.06344,-30.46281zM58.48,34.4c-4.50156,0 -9.23156,1.29 -13.76,5.21375c-2.365,2.06938 -2.15,5.49594 0.01344,4.43438c3.82969,-1.86781 7.25625,-2.76813 10.30656,-2.76813c9.245,0 13.85406,10.83063 15.265,12.255c2.01563,2.01563 5.28094,2.01563 7.31,0c2.01563,-2.01562 2.01563,-5.28094 0,-7.31c-1.26312,-1.24969 -7.31,-11.825 -19.135,-11.825zM113.52,34.4c-11.825,0 -17.87187,10.57531 -19.135,11.825c-2.01562,2.02906 -2.01562,5.29438 0,7.31c2.02906,2.01563 5.29438,2.01563 7.31,0c1.41094,-1.42437 6.02,-12.255 15.265,-12.255c3.05031,0 6.47688,0.90031 10.30656,2.76813c2.16344,1.06156 2.37844,-2.365 0.01344,-4.43438c-4.52844,-3.92375 -9.25844,-5.21375 -13.76,-5.21375zM19.92781,44.72c0.67187,0.05375 2.48594,0.71219 7.33687,3.60125c0.92719,0.55094 1.58563,0.90031 1.78719,0.9675c1.14219,0.43 1.90812,1.66625 1.90812,3.05031c0,1.04812 -0.43,1.77375 -0.80625,2.20375l-1.85437,2.21719l1.85437,2.21719c0.37625,0.43 0.80625,1.16906 0.80625,2.20375c0,1.38406 -0.76594,2.62031 -1.90812,3.05031c-0.20156,0.06719 -0.86,0.41656 -1.80063,0.9675c-4.8375,2.88906 -6.65156,3.5475 -7.29656,3.60125c-1.51844,0 -2.75469,-1.43781 -2.75469,-3.19812c0,-1.03469 0.43,-1.77375 0.80625,-2.20375l1.85438,-2.21719l-1.85438,-2.21719c-0.37625,-0.43 -0.80625,-1.16906 -0.80625,-2.20375c0,-1.03469 0.43,-1.77375 0.80625,-2.20375l1.85438,-2.21719l-1.85438,-2.21719c-0.37625,-0.43 -0.80625,-1.16906 -0.80625,-2.20375c0,-1.76031 1.23625,-3.19813 2.72781,-3.19813zM152.04531,44.72c1.51844,0 2.75469,1.43781 2.75469,3.19813c0,1.03469 -0.43,1.77375 -0.80625,2.20375l-1.84094,2.21719l1.84094,2.21719c0.37625,0.43 0.80625,1.16906 0.80625,2.20375c0,1.03469 -0.43,1.77375 -0.80625,2.20375l-1.84094,2.21719l1.84094,2.20375c0.37625,0.44344 0.80625,1.1825 0.80625,2.21719c0,1.76031 -1.23625,3.19812 -2.72781,3.19812c-0.65844,-0.04031 -2.48594,-0.71219 -7.32344,-3.60125c-0.92719,-0.55094 -1.58562,-0.90031 -1.78719,-0.9675c-1.14219,-0.43 -1.92156,-1.66625 -1.92156,-3.05031c0,-1.04812 0.43,-1.77375 0.80625,-2.21719l1.84094,-2.20375l-1.84094,-2.20375c-0.37625,-0.44344 -0.80625,-1.1825 -0.80625,-2.21719c0,-1.38406 0.76594,-2.60688 1.89469,-3.05031c0.215,-0.06719 0.87344,-0.41656 1.80063,-0.9675c4.85094,-2.88906 6.665,-3.5475 7.31,-3.60125zM60.2,58.49344c-5.17344,0 -12.04,2.91594 -12.04,9.83625c0,6.86656 6.53063,2.52625 11.70406,2.52625c5.17344,0 12.37594,3.93719 12.37594,-1.37062c0,-5.32125 -6.86656,-10.99188 -12.04,-10.99188zM111.8,58.49344c-5.17344,0 -12.04,5.67063 -12.04,10.99188c0,5.30781 7.2025,1.37062 12.37594,1.37062c5.17344,0 11.70406,4.34031 11.70406,-2.52625c0,-6.92031 -6.86656,-9.83625 -12.04,-9.83625zM68.96125,100.82156c1.8275,1.16906 3.91031,1.96187 6.07375,2.28437c2.44563,2.24406 6.26188,3.49375 10.965,3.49375c4.71656,0 8.51938,-1.24969 10.965,-3.49375c2.17688,-0.3225 4.24625,-1.11531 6.07375,-2.28437c1.66625,1.23625 3.80281,3.21156 5.13313,4.46125c4.50156,4.17906 8.76125,8.12969 13.94812,8.12969c6.20813,0 11.7175,-2.99656 15.17094,-7.6325c-1.22281,5.64375 -6.07375,11.23375 -11.47562,12.7925c-6.20813,1.77375 -8.97625,1.8275 -22.61531,1.8275h-34.4c-13.63906,0 -16.40719,-0.05375 -22.61531,-1.84094c-5.41531,-1.55875 -10.25281,-7.14875 -11.47562,-12.77906c3.44,4.63594 8.96281,7.6325 15.17094,7.6325c5.20031,0 9.44656,-3.95062 13.96156,-8.12969c1.33031,-1.24969 3.45344,-3.225 5.11969,-4.46125zM42.355,124.41781c0.645,0.25531 1.27656,0.56437 1.935,0.7525c7.14875,2.05594 10.72313,2.10969 24.51,2.10969h34.4c13.78688,0 17.36125,-0.05375 24.51,-2.10969c0.65844,-0.18813 1.29,-0.49719 1.935,-0.7525c-4.3,9.47344 -8.88219,12.69844 -11.34125,14.405c-1.1825,0.80625 -2.41875,1.54531 -3.60125,2.2575c-4.27312,2.51281 -10.07812,5.95281 -10.22594,13.42406c-0.80625,1.3975 -5.01219,3.73562 -8.15656,3.73562h-20.64c-3.14437,0 -7.35031,-2.33812 -8.15656,-3.73562c-0.14781,-7.47125 -5.95281,-10.91125 -10.22594,-13.42406c-1.1825,-0.71219 -2.41875,-1.45125 -3.60125,-2.2575c-2.45906,-1.70656 -7.04125,-4.93156 -11.34125,-14.405z"></path></g></g></svg><h1>ISPLOIT</h1>{t}<script>{script}</script></body></html>'
    
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

def apicall(domain,cur,mthod,key):
    api=INFOSPLOIT(domain,key)
    db.domains.insert_one({'domain':domain,'json':str(api.rslt),'html':api.html,'timestamp':cur})
    if mthod=="GET":return api.html
    else:return api.rslt

@app.route('/',methods=['GET','POST'])
def index():
    apidb=[i for i in db.domains.find({'domain':'nmap.com'})]
    if request.method=="GET":return apidb[-1]['html']
    else:return apidb[-1]['json']

# Speed up process now take 1 min to complete result
@app.route('/<url>/<key>',methods=['GET','POST'])
def isploi(url,key):
    domain='.'.join(url.split("://")[-1].split("/")[0].split('.')[-2:])
    apidb=[i for i in db.domains.find({'domain':domain})]
    cur=datetime.now().strftime('%m')
    if not apidb:return apicall(domain,cur,request.method,key)
    else:
        if int(apidb[-1]['timestamp']) < int(cur):
            db.domains.delete_one(apidb[-1])
            return apicall(domain,cur,request.method,key)
        else:
            if request.method=="GET":return apidb[-1]['html']
            else:return apidb[-1]['json']

if __name__=="__main__":
    app.run()