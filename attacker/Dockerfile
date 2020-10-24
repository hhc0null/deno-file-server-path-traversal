FROM python:3.8.6-alpine3.12 AS deps

LABEL maintainer="Hiroki Matsukuma <bugbounty.hhc0null@gmail.com>"

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

FROM python:3.8.6-alpine3.12

LABEL maintainer="Hiroki Matsukuma <bugbounty.hhc0null@gmail.com>"

COPY --from=deps /usr/local/lib/python3.8 /usr/local/lib/python3.8
COPY exploit.py exploit.py

CMD [ "python", "exploit.py" ]
