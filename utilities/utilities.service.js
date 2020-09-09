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

async function enable(id){
    const utility = await getUtility(id);
    utility.status = true;
    utility.modified = Date.now();
    await utility.save();
}

async function disable(id){
    const utility = await getUtility(id);
    utility.status = false;
    utility.modified = Date.now();
    await utility.save();
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

    const utility = new db.Utilities();
    utility.name = params.name;
    utility.status = params.status;
    utility.modified = Date.now();
    await utility.save();
    return utilityDetails(utility);
}

async function update(id, params) {
    const utility = await getUtility(id);

    // validate
    if (utility.name !== params.name && await db.Utilities.findOne({ name: params.name })) {
        throw 'Utility "' + params.name + '" already exists';
    }

    // copy params to utility and save
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
