const { MongoClient} = require('mongodb');
const commonOperation = require('./commonOperation');
const { log } = require('util');

const mongoConfig = commonOperation.readJsonFiles('config/mongoConfig.json');
const MONGO_CONNECTION_CONFIG = mongoConfig;
// console.log('mongoConfig :', mongoConfig);

async function connectMongo(MONGO_CONNECTION_CONFIG) {
    try {
      
        var url
        if (MONGO_CONNECTION_CONFIG.DB_CONNECTION_TYPE == "ATLAS") {
            CONNECTION_DETAILS = MONGO_CONNECTION_CONFIG.MONGO_ATLAS_CONNECTION
            url = `mongodb+srv://${CONNECTION_DETAILS.user}:${CONNECTION_DETAILS.password}@${CONNECTION_DETAILS.host}/${CONNECTION_DETAILS.databaseName}?retryWrites=true&w=majority&appName=Cluster0`;
            // url = `mongodb+srv://cchiku1999:4WqX3s8paabc2y4o@cluster0.sklu9w7.mongodb.net/myMongoDB?retryWrites=true&w=majority&appName=Cluster0`
            // url =`mongodb+srv://Debasmita:wXCdLdnBKqhs0W2D@cluster0.mxhweff.mongodb.net/myMongoDB?retryWrites=true&w=majority&appName=Cluster0`
        } else {
            CONNECTION_DETAILS = MONGO_CONNECTION_CONFIG.auth
            url = `mongodb://${CONNECTION_DETAILS.user}:${CONNECTION_DETAILS.password}@${CONNECTION_DETAILS.host}:${CONNECTION_DETAILS.port}/?authSource=${CONNECTION_DETAILS.databaseName}&authMechanism=${CONNECTION_DETAILS.authMechanism}`;
        }
        const client = new MongoClient(url);
        await client.connect();
        console.log("=====>CONNECTED TO MONGO_DB<=====");
        return client.db();
    } catch (err) {
        console.error("error in mongo connection:", err);
        return null;
    }
}
let db;
async function connect() {
    db = await connectMongo(MONGO_CONNECTION_CONFIG);
}
connect();
class MongoDBManager {
    constructor() {
        
    }

    getCollection(collection_name) {
        return db.collection(collection_name);
    }

    async insertDocument(collection_name, document) {
        try {
            const collection = this.getCollection(collection_name);
            const result = await collection.insertOne(document);
            console.log(`Document inserted with ID: ${result.insertedId}`);
        } catch (err) {
            console.error("Error in inserting document:", err);
        }
    }
    async insertManyDocuments(collectionName, documents) {
        try {
            const collection = this.getCollection(collectionName);
            const result = await collection.insertMany(documents);
            console.log(`Documents inserted with IDs: ${result.insertedIds}`);
        } catch (err) {
            console.error("Error in inserting documents:", err);
        }
    }

    async updateDocument(collectionName, filterQuery, updateData) {
        try {
            console.log('collectionName--', collectionName, 'filterQuery', filterQuery, 'updateData', updateData);
            const collection = this.getCollection(collectionName);
            const result = await collection.updateOne(filterQuery, updateData);
            console.log(`Matched ${result.matchedCount} document(s) and modified ${result.modifiedCount} document(s)`);
        } catch (err) {
            console.error("Error in updating document:", err);
        }
    }

    async deleteDocument(collectionName, filterQuery) {
        try {
            const collection = this.getCollection(collectionName);
            const result = await collection.deleteMany(filterQuery);
            console.log(`Deleted ${result.deletedCount} document(s)`);
        } catch (err) {
            console.error("Error in deleting document:", err);
        }
    }

    async findDocuments(collectionName, query = {}, projection = null) {
        try {
            // const collection = this.getCollection(collectionName);
            // const cursor = collection.find(query, projection);
            // const listCursor = await cursor.toArray();
            // if (listCursor.length > 0) {
            //     return listCursor;
            // } else {
            //     console.log("No documents found");
            //     return [];
            // }
            const data=db.collection(collectionName).find(query,projection).toArray()
            //  const listCursor = await cursor.toArray();
            return data

        } catch (err) {
            console.error("Error in finding documents:", err);
            return [];
        }
    }

    async aggregateDocuments(collectionName, pipeline, projection = null) {
        try {
            const collection = this.getCollection(collectionName);
            if (projection) {
                pipeline.push({ $project: projection });
            }
            const result = await collection.aggregate(pipeline).toArray();
            return result;
        } catch (err) {
            console.error("Error in aggregation:", err);
            return [];
        }
    }

    // Implement other methods similarly
}

// const mongoDBManager = new MongoDBManager(auth.databaseName);
// Now you can use mongoDBManager to perform MongoDB operations
module.exports = MongoDBManager;

