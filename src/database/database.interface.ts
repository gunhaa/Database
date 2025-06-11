export default interface database {
    getConnection(): void;
    query(): any;
}