## Natas
#### Level 0
As explained in the Natas description, each level has its own website accessible via `https://natasX.natas.labs.overthewire.org`, where `X` is the level number. For every level, you will need to input the username which is in the format `natasX` where again `X` is the level number, and the password. Each level has access to the password for the next level.

To login to the preliminary level:

> URL: http://natas0.natas.labs.overthewire.org
>
> Username: natas0
>
> Password: natas0

---

#### Level 1
You can always view the page source of a website by right clicking anywhere and navigating to the "View Page Source" or "Inspect" option (for Google Chrome, but this may be slightly different for other web browsers).

From the HTML, you can easily find the password for natas1 as a comment.

Comments in HTML are written like this: `<!--Here is some comment-->`

Password: 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq

---

#### Level 2
Removing the ability to right click does not mean you cannot access the page source. This can still be accessed by going to the three vertical dots at the top right in the Chrome browser, "More Tools", and then "Developer Tools".

Navigate to the "Elements" tab and you will be able to view the page source.

Password: TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI

---

#### Level 3
If you view the page source this time, you will no longer be able to find an easily accessible password in the form of a comment. The only thing you will find is an `<img>` tag with the source in `files/pixel.png`.

You can navigate to this directory by appending it to the end of the website URL like this:

`http://natas2.natas.labs.overthewire.org/files`

This brings you to a list of files, with the already seen `pixel.png` but curiously another file called `users.txt`.

Traveling to this link displays the contents of the text file, with the password for natas3 being in there.

Password: 3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH

---

#### Level 4
There is a new comment this time in the page source, "No more information leaks!! Not even Google will find it this time...". This suggests there is something that can be hidden from Google, or all search engines for that matter.

All search engines typically use what's known as a [webcrawler](https://www.cloudflare.com/en-gb/learning/bots/what-is-a-web-crawler/) which is a bot that 'crawls' the entire internet, or in other words, scrapes as much data as possible on every website which can then be fed through a search algorithm to organize each one so that search engines can provide relevant website results to user queries.

However, web crawlers are not always allowed to traverse every page and link on a website. They must follow what's known as the robots.txt protocol.

Most websites have a file named `robots.txt` in the source files and this dictates what pages and links web crawlers can and cannot access. You can have a look at the file by appending `robots.txt` to the website URL.

`http://natas3.natas.labs.overthewire.org/robots.txt`

This takes you to the file, where it says that it does not allow the webpage `/s3cr3t/` to be accessed by crawlers. Navigate to this page:

`http://natas3.natas.labs.overthewire.org/s3cr3t/`

This will bring you to a list of files with another `users.txt` file. Entering this link gives you the password for the next level.

Password: QryZXc2e0zahULdHrtHxzyYkj59kUxLQ

---

#### Level 5
After accessing the page you are greeted with a message, "Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/".

The message will be different depending on from where you accessed the site.

Websites know where you came from to reach the site (i.e. the address of the prior webpage). This is known as the [Referer](https://en.wikipedia.org/wiki/HTTP_referer). It is often used as a means to track users for statistical or promotional purposes.

There are numerous ways you can spoof the website into thinking you came from "http://natas5.natas.labs.overthewire.org/". You could write a Python script, or use software that can intercept requests before it loads. The latter will be used to get an idea of how Burp Suite works.

If you open up Burp Suite and go to the 'Proxy' tab, you will be able to turn on Intercept. This will make it so every request is intercepted and put on hold, allowing you to observe each request and make adjustments before forwarding it.

Once Intercept is turned on, open up the built-in browser and head to "http://natas4.natas.labs.overthewire.org/". You will find an HTTP request in the Intercept window. Click on it and add a line in the raw request field:

`Referer: http://natas5.natas.labs.overthewire.org/`

Forward the request and the message should change.

Password: 0n35PkggAPm2zbEpOU802c0x0Msn1ToK

---

#### Level 6
After entering the webpage, you are again greeted with a message but this time it says, "Access disallowed. You are not logged in".

Unlike the previous level, we are given less of a hint on what to do and where to look. However, the key message is that the website somehow knows that you are not logged in.

You may have noticed if you have been on the internet before, that you don't need to login repeatedly everytime you access a particular website if you have already logged in once. Websites use something called [cookies](https://en.wikipedia.org/wiki/HTTP_cookie#Session_management) to remember information about a user. Cookies are stored on the user's device while they are browsing, holding useful data such as a 'state' like items that have been added to a shopping cart, or to save previously entered input in text fields like addresses.

You can make use of Burp Suite again to intercept the request when accessing the natas5 webpage.

This time you will find a field called "Cookie" in the request with `loggedin=0`. Simply change this to a 1 before forwarding and you will be given the password for natas6.

Password: 0RoJwHdSKWFTYR5WuiAewauSuNaBXned

---

#### Level 7
This time you are greeted with a form that asks you to input a 'secret'. You can try inputting an arbitrary string such as '1234', but this gives a message that says, "Wrong secret" at the top.

The first most obvious step is to check the source code, which the site has already given a handy link to. Upon going through it, you will find that there is a piece of PHP code out in the open that includes the file path `includes/secret.inc` to access the variable `$_POST['secret']`.

Navigate to `http://natas6.natas.labs.overthewire.org/includes/secret.inc` to find the aforementioned secret.

Lastly, input the secret into the form and you will receive the passsword for natas7.

Password: bmg8SvU1LizuWjx3y7xkNERkHxGre0GS

---

#### Level 8