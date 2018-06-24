import * as http from 'http';
import Server from "./server";
import "reflect-metadata";  // Required for Typedi

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';

const server = http.createServer(Server);

server.listen(PORT, HOST, () => console.log(`Server listening on host ${HOST} port ${PORT}.`));
