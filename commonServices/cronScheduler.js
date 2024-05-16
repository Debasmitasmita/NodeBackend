const schedule = require('node-schedule');
const fs = require('fs');
const { DateTime } = require('luxon');
const { sendEmail } = require('./commonOperation');
const MongoDBManager = require('./mongoServices');
let {readJsonFiles} = require('./commonOperation');
const otherConfig = readJsonFiles('./config/otherFeaturesConfigs.json');
mongoDBManagerObj = new MongoDBManager(); 

const lockFilePath = './scheduler.lock';
//scheduler lock file should be removed before running the scheduler
function acquireLock(callback) {
    fs.open(lockFilePath, 'wx', (err, fd) => {
        if (err) {
            if (err.code === 'EEXIST') {
                console.log('Lock file already exists. Another process may be running the scheduler.');
            } else {
                console.error('Error acquiring lock:', err);
            }
            return;
        }
        // Lock acquired successfully
        fs.close(fd, callback);
    });
}

function releaseLock() {
    fs.unlink(lockFilePath, (err) => {
        if (err) {
            console.error('Error releasing lock:', err);
        } else {
            console.log('Lock released successfully.');
        }
    });
}

function scheduleTask(taskName, cronExpression, callback) {
    acquireLock(() => {
        const job = schedule.scheduleJob(taskName, cronExpression, callback);
        console.log(`Scheduled task '${taskName}' with cron expression '${cronExpression}'`);
    });
}

// Example usage
function myTask() {
    console.log("Executing my task at", new Date());
}
async function emailFailureRetryAttempt() {
    try {
        console.log("emailFailureRetryAttempt :", DateTime.now());
        const threeDaysAgo = DateTime.now().minus({ days: 3 }).toJSDate();
        // Query to retrieve data from the last 3 days
        const data = await mongoDBManagerObj.findDocuments(
            otherConfig["emailConfig"]["retryMailCol"],
            { timestamp: { $gte: threeDaysAgo } },
            {}
        );
        // console.log("data Attempt :", data);
        if (data.length === 0) {
            console.log("-------No retry attempt----");
        } else {
            let i =0;
            let emailSend = setInterval(function () {
                console.log("emailFailureRetryAttempt :", DateTime.now());
                let subject = data[i].subject;
                let body = data[i].body;
                let toEmail = data[i].toEmail;
                console.log("id :",data[i]._id.toString(),'subject', data[i].subject,  "toEmail :", data[i].toEmail);
                sendEmail(subject =subject, body= body, toEmail= toEmail,retryId = data[i]._id.toString());
                i++;
                if(i== data.length){
                    clearInterval(emailSend);
                }
            }, 1500);
        }
    } catch (err) {
        console.log("Error in emailFailureRetryAttempt:", err);
    }
}

// Define your task settings
const taskName = "emailFailureRetryAttempt";
const cronExpression = "* * */4 * * *"; // Every 5 minutes

// Schedule the task
// releaseLock();
scheduleTask(taskName, cronExpression, emailFailureRetryAttempt);
module.exports = {
    scheduleTask,
    releaseLock
};
