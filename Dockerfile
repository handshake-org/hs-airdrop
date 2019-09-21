FROM node
COPY . .
ENV BUILD_DIR hs-tree-data
RUN npm i & git clone https://github.com/handshake-org/hs-tree-data.git
ENTRYPOINT ["./bin/hs-airdrop"]
