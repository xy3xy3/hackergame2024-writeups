FROM node:23-alpine

COPY web /web/
WORKDIR /web/
RUN npm install

#RUN echo "Submit your payload to get real flag on server!" > /flag

USER node
CMD ["node", "/web/server.js"]
