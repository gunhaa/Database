import RawMySQLClient from "./database/RawMySQLClient";

const client = new RawMySQLClient();
client.getConnection();