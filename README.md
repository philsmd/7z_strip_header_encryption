# About

This little `7z_strip_header_encryption` POC (proof of concept) was actually planned to only show a very specific problem with `7-Zip` files that were generated by adding files with data encryption enabled (`-p`) but without header encryption with a first password and afterwards **modifying** this 7-Zip file by running a `7z a` command (i.e. add file to 7-Zip archive) with `-p -mhe=on` (or short: `-p -mhe`) option (i.e. with header encryption enabled) with a second/**different** password.  
\
This specific case/scenario makes most of the archive viewing and archive extracting ("archiver") tools (including `p7zip`/`7z` and other 3rd party tools like `ark`/`peazip` and many others) fail to decompress/extract the data. The most likely reason is these utilities are confused by this 2-password (you could also think of multi-layer) encryption. Some of these tools might just be confused why the first (wrong/"other") password that the user provided does not work, without even asking for a different password. Some tools ask the user again after failure to decrypt with the outer password whenever the first password was correct and the tool succeeded in showing all the files included, but then it seems that they still can't extract the data, probably because they "forgot" the first password (yeah, it seems weird that they behave like this). The main problem is that `7z` itself allows you to generate such archives (with 2 layers), without any errors or warnings.  

Most utilities are able to decrypt the first layer (the header encryption) with the correct password, but don't allow you to decrypt and open the **included** files or only the few ones that use the **same** password as the header encryption (the "other layer").  

Note that this problem does of course not occur if you try to "open" files that also require a password after they were already extracted (just imagine it like this: this is a completely separate file and a completely different extraction task), like nested `.7z` files with different passwords. This specific case is not handled by this tool and also seems to just work fine by every decompression tool. In general, it seems that most tools behave very similar to `7z` from `7-zip.org` or `p7zip` (just another user interface or graphical user interface, GUI, around it). Therefore it might be reasonable to assume that they just inherited the problem from the `7z` tool, that they might use as code base or library.  

It also seems that different passwords for the individual files within the same "layer" (i.e. not comparing header encryption versus file encryption), added by `7z a` for instance, but without using header encryption, is no problem for most tools.  

Remember that many people could easily accidentally end up in a "problematic" situation like this, after they have created an archive file with several important files (some of them, but not necessarily all of them, they might even consider very important and sensitive such that they used password-protection/encryption) and while adding and adding files to the archive they also run a command that encrypts the whole file list too (now it is important here if they used the exact same password for this layer too - in that case they won't have a problem extracting it also without `7z_strip_header_encryption` -, but as we could imagine, people, while performing that specific step, could have easily forgotten that the archive already contains encrypted file data or that the internal password was a different one).  

Indeed this situation is a quite common approach. For instance, the owner of the file might take a further look at the `7-Zip` archive that they have created and later on discover that the file list is still not protected and that the file could also be easily manipulated by strangers without providing a password. Therefore they decide to go a step further and add also the file list (i.e. header) encryption. In fact, this is something that is recommended a lot on internet forums and discussions, i.e. to perform this extra step, that in this specific case (if different passwords were used for the 2 layers) could make your whole data seemingly unreadable/locked-in.  
\
\
The **goal** of this project is to highlight and emphasize the actual underlying problem that could also potentially be misused to trick people or victims to just ignore these "seemingly corrupted" or not working `7-Zip` files. This tool shows that you could easily "strip" the outer password encryption layer (i.e. the encrypted header, the password-protected structure added with `-p -mhe=on`, i.e. the encrypted file/folder structure with metadata, timestamps, checksums etc).  

This tool can be combined with `7z2hashcat` and `hc_to_7z` to form a suite of tools, that you can use to analyze and, in general, deal with all kind of password-protected `7-Zip` files.
\
\
While investigating this problem I've also noticed a very different and unrelated but also interesting bug in many 3rd party tools: many tools don't allow you to extract the data with **empty password** (zero length). While the `p7zip` and `7z` tool allow you to create such archives (you can use empty passwords for both `-p` and `-p -mhe=on`), many viewers/tools fail to extract the data if you provide an empty password (because they think you didn't provide/specify any password). This problem also could confuse many users. People could "hide" data and the "receiver" of the `7-Zip` file (or the forensic investigator, malware hunter or data recovery specialist) could just give up, even if the password is so simple (i.e. the empty password).

# Requirements

Software:  
- Perl must be installed (should work on *nix and windows with `perl` installed)
- Perl modules `Compress::Raw::Lzma`, `Crypt::CBC`, `Digest::CRC`, `Digest::SHA` and `Encode` are required
    - example on how to install modules with cpan:  
    `sudo cpan Compress::Raw::Lzma Crypt::CBC Digest::CRC Digest::SHA Encode`  
    - example on how to otherwise install modules on debian/ubuntu:  
    `sudo apt install libdigest-crc-perl`  
    - optionally install `File::Glob` for file globbing (i.e. `*.7z`) under Windows OS

# Installation and first steps

* Clone this repository:  
    ```git clone https://github.com/philsmd/7z_strip_header_encryption```
* Enter the repository root folder:  
    ```cd 7z_strip_header_encryption```
* Run it in your terminal/shell/cmd:  
    ```perl 7z_strip_header_encryption.pl --password 1234 ../encrypted.7z```
* Open the output file with your preferred archive tool/viewer
  
Note that `7z_strip_header_encryption` is a terminal application. This means that you need to open your shell program like `cmd` or `konsole`/`shell`/`xterm` first and afterwards run this `perl` script. If you are confused by a window that just opens for a few instants and immediately closes, you need to get comfortable with cmd/shell.

# Command line parameters

The usage is very simple: you just specify the path to the `7-Zip` file and also provide the password to the tool with the `--password` (or short `-p`) command line option.  
  
You can also use multiple files on the command line like this (but they need to have the same header encryption password):  
```
perl 7z_strip_header_encryption.pl -p *.7z
perl 7z_strip_header_encryption.pl -p 7z/*
```
   
   
More example commands:
```
perl 7z_strip_header_encryption.pl -p1 1.7z
perl 7z_strip_header_encryption.pl --version
perl 7z_strip_header_encryption.pl --help
perl 7z_strip_header_encryption.pl -p password -o output.7z a.7z
./7z_strip_header_encryption.pl -p 1234 *.7z
```


Note that if you do not want to specify the password within your command line, `7z_strip_header_encryption` will interactively ask for the password input if you just leave the `-p` command line switch without any argument, e.g. `perl 7z_strip_header_encryption.pl -p encrypted.7z`.

# Usual invocation of `7z_strip_header_encryption`

It only makes sense to run this tool if at least the header encryption step was performed while compressing the data. Without any header encryption, `7z_strip_header_encryption` will refrain to work and show an error.  

The following steps show you what the "discovered" underlying problem is:
1. create a first file like this: `echo -n 1 > 1`
2. create a second file like this: `echo -n 2 > 2`
3. add one file to a new `7-Zip` archive like this: `7z a -p2 a.7z 2`
4. add another file to the same archive, but also add header encryption: `7z a -p1 -mhe=on a.7z 1`\
(optionally: you could now also delete the second/extra file, it doesn't change anything except that the file size and file list gets even smaller: `7z d -p1 a.7z 1`)
5. try to extract the data with `7-Zip` tools/viewers: `7z x -p1 a.7z` (this will fail, you have now locked-in your important data. Yeah, this seems like `7-Zip` is refusing to give you your data back, a kind of "denial of service" situation. No matter what you do, it won't decrypt/extract it)
6. run `7z_strip_header_encryption`: `perl 7z_strip_header_encryption.pl -p1 -o output.7z a.7z`
7. you will immediately notice that while opening the file `a.7z` you are asked for a password (`7z l a.7z`), the newly generated output file will immediately show the whole file list and you can now extract the data correctly with `7z x -p2 output.7z` (important you now need to use the second/inner password !). This means, that with this combination of commands we are now able to specify both passwords (password "1" and password "2") and are finally able to get our data back.  

\
It is indeed possible to run the command `7z l -p1 a.7z` (i.e. with the original, double-layered file) to see a list of all contained files without any errors, by specifying the correct password, but the extraction (`7z x -p1 a.7z`) will still fail. Only `7z_strip_header_encryption` helps here to get rid of the outer layer and therefore remove "password 1" (`-p1`).

Instead of using `-p1` and `-p2` you could use any other passwords, but you must make sure that password 2 is different from password 1 (for example `-phunter2` for password 1 and `-phashcatrocks` for password 2), otherwise it will just accidentally work fine (also without running `7z_strip_header_encryption`).  

You might also observe that several tools are able to extract some of the files without any problem, this is because these specific files that are correctly extracted were encrypted with the same password (the final `7z a -mhe=on a.7z 1` adds a file with file name "1" that is encrypted with that specific password, while also generating encrypted headers).  
\
\
Another interesting observation is that this tool (just by chance) also works if you only have 1 single outer (i.e. `-p -mhe=on`) password layer (again, this is of course not the main goal, nor the intended task, that `7z_strip_header_encryption` should accomplish).\
\
Use these commands to generate it:
1. `echo -n 1 > 1`
2. `7z a -p1 -mhe=on a.7z 1`
3. `perl 7z_strip_header_encryption.pl -p 1 a.7z`

The interesting thing here is that it doesn't remove the (or all) password(s) completely. The underlying data still uses password-protection and encryption, but you can now see the file list without specifying a password. This is of course not something that `7z_strip_header_encryption` does handle very specifically or specially/differently, this is just how the `7-Zip` file format is designed, i.e. the coders still apply with all the coders attributes and the data is still encrypted (just the header encryption, i.e. encrypted file list including metadata etc, was decrypted and the decrypted header is used for the `7z_strip_header_encryption` output file, i.e. the encrypted header is stripped, the real data stream is not modified. On the other hand, some parts in the `7z_strip_header_encryption` code (search for `$second_layer_pass`) even show you how to also decrypt the underlying data with the correct/second password, so it's also not impossible to do, even with just in-memory/RAM buffers).
\
\
\
Another special case would be to add (`7z a -p1 a.7z 1`) the same file twice (`7z a -p2 -mhe=on a.7z 1`), i.e. once without and once with header encryption, but in this specific case we just replace the first file addition and therefore every tool seem to handle this correctly (no need for `7z_strip_header_encryption` in this specific situation).

# Implications

I think this `7z_strip_header_encryption` demonstrates in a very simple way that it is indeed possible to use 2 different passwords and therefore a multi-layer approach, i.e. both encrypted files (`-p`) and in addition to that, enable header encryption (`-p -mhe=on`) and still be able to compress and decompress the encrypted data with very simple means. Note that there are several sources on the internet that claim the opposite and even explain that the data now is lost etc.   

It also shows that it's quite easy to use existing code (like `7z2hashcat`/`hc_to_7z`) and modify libraries (`p7zip`/`7z` code etc, not shown here, but the concept is the same as demonstrated by modifying code from `7z2hashcat`) to simply extract data that many tools completely fail to extract (they only show that data is corrupt or, in other cases, that the password is wrong).  

The main implication is that the underlying problem is quite dangerous for users such that they **accidentally** add files like this and don't even understand why they can't unlock **their own files** later on. They might even think they have now lost all their important data.  

Some related resources and answers by the `7z` authors:
- https://sourceforge.net/p/sevenzip/discussion/45798/thread/fd0f7ca192/#8e40
- https://sourceforge.net/p/sevenzip/discussion/45798/thread/44b632a5/
- https://sourceforge.net/p/sevenzip/discussion/45798/thread/f0ddb752/#ff03  

etc   


In other scenarios this knowledge can be easily used to **trick** other people into ignoring files or even worse by **malware** to "hide" data that most anti-virus tools, but also security researchers and forensic investigators, could just not be able to easily deal with and therefore they might ignore them completely.  

Yeah, we all know that at some point a `7-Zip` file for instance sent via mail somehow needs to be extracted (and files included need to be executed) first before something evil could happen. Don't get confused/tricked by this fact, because malware authors could easily use this "strange" double-encryption to hide some data (even in memory/RAM only) e.g. some trojan horses using in-memory decompression and hiding data that can't be easily recovered without applying the strategy of `7z_strip_header_encryption` etc.  

This non-intuitive behavior and at the same time still allowing people to generate such archives without letting them open these files easily is quite dangerous and shocking.  

During this investigation I've even tested some common anti-virus products and run tests with services like `virustotal.com`. As already guessed, most anti-virus tools don't really care about analysing these password-protected archives or fail in doing so. Of course, the anti-virus vendors might just argue that it is impossible to deal with encrypted archives for which the passwords are unknown and too hard to guess. In most cases it didn't even work with very simple or even zero-length (empty) passwords (but still encrypted). In general, all files were incorrectly marked as clean even if they contained `EICAR` test files etc.  

This also shows us that when dealing with such complex archive formats, malware authors might just easily mess around with these special cases and even perform some anti-virus circumvention steps like faking/injecting a wrong and random `CRC` checksum to hide the real data (yeah, sometimes even `CRC32` checksums could be enough for malware researchers to understand what files it contained, even without knowing the encryption password). Faking the checksums therefore has at least two important implications, i.e. you can't really tell what the extracted file is by just looking at the checksums and that you could misuse this to make it kind of impossible for investigators to know if the extraction works correctly (because the checksum check is also used to verify if the password is the correct one).  
\
\
For the `7z` command line tool we can just observe that it would probably make sense to allow the user to specify both the header encryption password and the passwords for the single files. On the other hand, the tools (not only `7z` itself is affected by this problem) could and should interactively ask the passwords for each and every included file during decompression/opening, while still correctly keeping and managing the outer password for the header encryption to be able to correctly extract  both the metadata and important file data from the whole archive that was generated with more than 2 passwords.

# Proof of concept / experimental warning

Please be aware that this tool is highly experimental and was originally meant only as a POC (proof of concept) to help understand the underlying problem with several decompression tools and archive viewers.

The support of unusual and more advanced combinations of `coders` and `preprocessors` (see `7z2hashcat` README from https://github.com/philsmd/7z2hashcat) is not supported yet (or only very limited support was added, untested).

# TODOs / Hacking / Missing features

* Consider reporting these "findings" as bugs, security problems and vulnerabilities (what could be the worse case of these "problems" reported here ?)
* Consider notifying and warning users about the mix of `-p` and `-p -mhe=on`. Where exactly ?
* Consider contacting maintainers and tool developers (also 3rd party) to at least get rid of user confusion and denial of service scenarios
* Help people get back their important encrypted locked-in data
* More features
* CLEANUP the code, refactor, use more coding standards, make it easier readable, everything is welcome (submit patches!)
* keep it up-to-date with `7z2hashcat` and `hc_to_7z`
* improvements and all bug fixes are very welcome
* solve and remove the github issues and TODOs within the code (if any exist)
* and,and,and

# Credits and Contributors

Credits go to:  
  
* philsmd, hashcat project

# License/Disclaimer

License: belongs to the PUBLIC DOMAIN, donated to hashcat, credits MUST go to hashcat and philsmd for their hard work. Thx  
  
Disclaimer: WE PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
NO GUARANTEES THAT IT WORKS FOR YOU AND WORKS CORRECTLY
