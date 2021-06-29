const fs = require('fs');
const crypto = require('crypto');
const util = require('util');
const Repository = require('./repository');

const scrypt = util.promisify(crypto.scrypt);

class UsersRepository extends Repository {
    async comparePasswords(saved, supplied) {
        const [hashed, salt] = saved.split('.');
        const hashedSuppliedbuf = await scrypt(supplied, salt, 64);

        return hashed === hashedSuppliedbuf.toString('hex');
    }

    async create(attrs) {
        attrs.id = this.randomId();

        const salt = crypto.randomBytes(8).toString('hex');
        const buf = await scrypt(attrs.password, salt, 64);
       

        const records = await this.getAll();
        const record = {
            ...attrs,
            password: `${buf.toString('hex')}.${salt}`
        };
        records.push(record);

        await this.writeAll(records); 

        return record;
    }
}


module.exports = new UsersRepository('users.json');

