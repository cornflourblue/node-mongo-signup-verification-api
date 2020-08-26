const db = require('_helpers/db');

module.exports = {
    enable,
    disable,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function enable(params){
    const utilities = await db.Utilities.findOne({name: params.name});

    if (!utilities) throw 'Invalid request';

    if (!utilities.isActive) {
        utilities.status = true;
        utilities.modified = Date.now();
        await utilities.save();
    }
}

async function disable(params){
    const utilities = await db.Utilities.findOne({name: params.name});

    if (!utilities) throw 'Invalid request';

    if (utilities.isActive) {
        utilities.status = false;
        utilities.modified = Date.now();
        await utilities.save();
    }
}

async function getAll() {
    const utilities = await db.Utilities.find();
    return utilities.map(x => utilityDetails(x));
}

async function getById(id) {
    const utility = await getUtility(id);
    return utilityDetails(utility);
}

async function create(params) {
    // validate
    if (await db.Utilities.findOne({ name: params.name })) {
        throw 'Utility "' + params.name + '" already exists';
    }

    const utilities = new db.Utilities();
    utilities.name = params.name;
    utilities.status = params.status;
    utilities.modified = Date.now();
    await utilities.save();
}

async function update(id, params) {
    // validate    
    if (await db.Utilities.findOne({ name: params.name })) {
        throw 'Utility "' + params.name + '" already exists';
    }

    const utility = await getUtility(id);

    // copy params to account and save
    Object.assign(utility, params);
    utility.modified = Date.now();
    await utility.save();

    return utilityDetails(utility);
}

async function _delete(id) {
    const utility = await getUtility(id);
    await utility.remove();
}

// helper functions

function utilityDetails(utilities) {
    const { id, name, status, modified } = utilities;
    return { id, name, status, modified };
}

async function getUtility(id) {
    if (!db.isValidId(id)) throw 'Utility not found';
    const utility = await db.Utilities.findById(id);
    if (!utility) throw 'Utility not found';
    return utility;
}
