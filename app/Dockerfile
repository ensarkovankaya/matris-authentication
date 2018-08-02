FROM node:10.7.0-jessie

WORKDIR /home/node/app
USER node

ENV NODE_ENV=prod

COPY ./ /home/node/app/

ENTRYPOINT /home/node/app/entrypoint.sh
