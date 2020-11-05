let jsrsasign = require('jsrsasign');

class Participant {
    constructor(selfPvtKey, otherPubKey) {
        this.selfPvtKey = selfPvtKey;
        this.otherPubKey = otherPubKey;
    }

    sign(data) {
        let sig = new jsrsasign.KJUR.crypto.Signature({"alg": "SHA256withRSA"});

        sig.init(this.selfPvtKey);
        sig.updateString(data);

        return sig.sign();
    }

    verify(data, sigValueHex) {
        let sig = new jsrsasign.KJUR.crypto.Signature({"alg": "SHA256withRSA"});

        sig.init(this.otherPubKey);
        sig.updateString(data);

        let isValid = sig.verify(sigValueHex);

        if(isValid) {
            this.otherChallenge = data.split("|")[1];
        }

        return isValid;
    }

    getChallenge() {
        let random = "";
        while(random.length < 128) {
            random += Math.random().toString(16).slice(2,10);
        }
        this.lastChallenge = random;
        return random;
    }
}

console.log("Generating key pairs for the car and the trinket");
// Генерация пары ключей для автомобиля и брелока
const carKeypair = jsrsasign.KEYUTIL.generateKeypair("RSA", 2048);
const trinketKeypair = jsrsasign.KEYUTIL.generateKeypair("RSA", 2048);
console.log("Keys generated!");
const Car = new Participant(carKeypair.prvKeyObj, trinketKeypair.pubKeyObj);
const Trinket = new Participant(trinketKeypair.prvKeyObj, carKeypair.pubKeyObj);

function trinketSendsSignedCommandAndRandomToCar() {
    let trinketMessage = "OPEN|" + Trinket.getChallenge();
    let trinketSign = Trinket.sign(trinketMessage);
    console.log("Trinket sends signed (command + challenge) to the car: " + trinketMessage);
    console.log("Trinket's signature: " + trinketSign);

    return {msg: trinketMessage, sgn: trinketSign};
}

function carVerifiesTrinketMessage(trinketMessage) {
    console.log("Car verifies trinket's message");
    let isValid = Car.verify(trinketMessage.msg, trinketMessage.sgn);
    if(!isValid) {
        throw new Error("Validation failed");
    }
}

function carSendsSignedRandomAndChallengeToTrinket() {
    let carMessage = Car.otherChallenge + "|" + Car.getChallenge();
    let carSign = Car.sign(carMessage);
    console.log("Car sends signed (trinket's challenge + car's challenge) to the trinket: " + carMessage);
    console.log("Car's signature: " + carSign);

    return {msg: carMessage, sgn: carSign};
}

function trinketVerifiesCarMessage(carMessage) {
    console.log("Trinket verifies car's message");
    let isValid = Trinket.verify(carMessage.msg, carMessage.sgn);
    if(!isValid || Trinket.lastChallenge !== carMessage.msg.split("|")[0]) {
        throw new Error("Validation failed");
    }
}

function trinketSendsSignedChallengeBackToCar() {
    let trinketReply = "|" + Trinket.otherChallenge;
    let replySign = Trinket.sign(trinketReply);
    console.log("Trinket sends signed car's challenge to the car: " + trinketReply);
    console.log("Trinket's signature: " + replySign);
    return {msg: trinketReply, sgn: replySign};
}

function carVerifiesReplyFromTrinket(trinketReply) {
    console.log("Car verifies challenge from trinket");
    let isValid = Car.verify(trinketReply.msg, trinketReply.sgn);
    if(!isValid || Car.lastChallenge !== Car.otherChallenge) {
        throw new Error("Validation failed");
    }
}

function carOpens() {
    console.log("Car opens!");
}

function openCar() {
    let trinketMessage = trinketSendsSignedCommandAndRandomToCar();

    carVerifiesTrinketMessage(trinketMessage);

    let carMessage = carSendsSignedRandomAndChallengeToTrinket();

    trinketVerifiesCarMessage(carMessage);

    let replyMessage = trinketSendsSignedChallengeBackToCar();

    carVerifiesReplyFromTrinket(replyMessage);

    carOpens();
}

openCar();