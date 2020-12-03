FROM binkhq/python:3.9

ARG commit
ENV SENTRY_RELEASE=$commit
ENV SENTRY_DSN="https://f902d5041ee947b1b24d75b24d11ad50@sentry.uksouth.bink.sh/24"

WORKDIR /app
ADD . .

RUN pip install pipenv && pipenv install --system --deploy --ignore-pipfile

CMD [ "python", "main.py" ]
