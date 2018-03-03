let serializeTransaction = function (entity) {
    var r = new ArrayBuffer(512 + 2764);
    var d = new Uint32Array(r);
    var b = new Uint8Array(r);
    d[0] = entity['type'];
    d[1] = entity['version'];
    d[2] = entity['timeStamp'];

    var temp = convert.hex2ua(entity['signer']);
    d[3] = temp.length;
    var e = 16;
    for (var j = 0; j < temp.length; ++j) {
        b[e++] = temp[j];
    }

    // Transaction
    var i = e / 4;
    d[i++] = entity['fee'];
    d[i++] = Math.floor((entity['fee'] / 0x100000000));
    d[i++] = entity['deadline'];
    e += 12;

    // TransferTransaction
    if (d[0] === TransactionTypes.transfer) {
        d[i++] = entity['recipient'].length;
        e += 4;
        // TODO: check that entity['recipient'].length is always 40 bytes
        for (var j = 0; j < entity['recipient'].length; ++j) {
            b[e++] = entity['recipient'].charCodeAt(j);
        }
        i = e / 4;
        d[i++] = entity['amount'];
        d[i++] = Math.floor((entity['amount'] / 0x100000000));
        e += 8;

        if (entity['message']['type'] === 1 || entity['message']['type'] === 2) {
            var temp = convert.hex2ua(entity['message']['payload']);
            if (temp.length === 0) {
                d[i++] = 0;
                e += 4;
            } else {
                // length of a message object
                d[i++] = 8 + temp.length;
                // object itself
                d[i++] = entity['message']['type'];
                d[i++] = temp.length;
                e += 12;
                for (var j = 0; j < temp.length; ++j) {
                    b[e++] = temp[j];
                }
            }
        }

        var entityVersion = d[1] & 0xffffff;
        if (entityVersion >= 2) {
            var temp = _serializeMosaics(entity['mosaics']);
            for (var j = 0; j < temp.length; ++j) {
                b[e++] = temp[j];
            }
        }

        // Provision Namespace transaction
    } else if (d[0] === TransactionTypes.provisionNamespace) {
        d[i++] = entity['rentalFeeSink'].length;
        e += 4;
        // TODO: check that entity['rentalFeeSink'].length is always 40 bytes
        for (var j = 0; j < entity['rentalFeeSink'].length; ++j) {
            b[e++] = entity['rentalFeeSink'].charCodeAt(j);
        }
        i = e / 4;
        d[i++] = entity['rentalFee'];
        d[i++] = Math.floor((entity['rentalFee'] / 0x100000000));
        e += 8;

        var temp = _serializeSafeString(entity['newPart']);
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp[j];
        }

        var temp = _serializeSafeString(entity['parent']);
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp[j];
        }

        // Mosaic Definition Creation transaction
    } else if (d[0] === TransactionTypes.mosaicDefinition) {
        var temp = _serializeMosaicDefinition(entity['mosaicDefinition']);
        d[i++] = temp.length;
        e += 4;
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp[j];
        }

        temp = _serializeSafeString(entity['creationFeeSink']);
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp[j];
        }

        temp = _serializeLong(entity['creationFee']);
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp[j];
        }

        // Mosaic Supply Change transaction
    } else if (d[0] === TransactionTypes.mosaicSupply) {
        var serializedMosaicId = _serializeMosaicId(entity['mosaicId']);
        for (var j = 0; j < serializedMosaicId.length; ++j) {
            b[e++] = serializedMosaicId[j];
        }

        var temp = new ArrayBuffer(4);
        d = new Uint32Array(temp);
        d[0] = entity['supplyType'];
        var serializeSupplyType = new Uint8Array(temp);
        for (var j = 0; j < serializeSupplyType.length; ++j) {
            b[e++] = serializeSupplyType[j];
        }

        var serializedDelta = _serializeLong(entity['delta']);
        for (var j = 0; j < serializedDelta.length; ++j) {
            b[e++] = serializedDelta[j];
        }

        // Signature transaction
    } else if (d[0] === TransactionTypes.multisigSignature) {
        var temp = convert.hex2ua(entity['otherHash']['data']);
        // length of a hash object....
        d[i++] = 4 + temp.length;
        // object itself
        d[i++] = temp.length;
        e += 8;
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp[j];
        }
        i = e / 4;

        temp = entity['otherAccount'];
        d[i++] = temp.length;
        e += 4;
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp.charCodeAt(j);
        }

        // Multisig wrapped transaction
    } else if (d[0] === TransactionTypes.multisigTransaction) {
        var temp = serializeTransaction(entity['otherTrans']);
        d[i++] = temp.length;
        e += 4;
        for (var j = 0; j < temp.length; ++j) {
            b[e++] = temp[j];
        }

        // Aggregate Modification transaction
    } else if (d[0] === TransactionTypes.multisigModification) {
        // Number of modifications
        var temp = entity['modifications'];
        d[i++] = temp.length;
        e += 4;

        for (var j = 0; j < temp.length; ++j) {
            // Length of modification structure
            d[i++] = 0x28;
            e += 4;
            // Modification type
            if (temp[j]['modificationType'] == 1) {
                d[i++] = 0x01;
            } else {
                d[i++] = 0x02;
            }
            e += 4;
            // Length of public key
            d[i++] = 0x20;
            e += 4;

            var key2bytes = convert.hex2ua(entity['modifications'][j]['cosignatoryAccount']);

            // Key to Bytes
            for (var k = 0; k < key2bytes.length; ++k) {
                b[e++] = key2bytes[k];
            }
            i = e / 4;
        }

        var entityVersion = d[1] & 0xffffff;
        if (entityVersion >= 2) {
            d[i++] = 0x04;
            e += 4;
            // Relative change
            d[i++] = entity['minCosignatories']['relativeChange'].toString(16);
            e += 4;
        } else {
            // Version 1 has no modifications
        }

    } else if (d[0] === TransactionTypes.importanceTransfer) {
        d[i++] = entity['mode'];
        e += 4;
        d[i++] = 0x20;
        e += 4;
        var key2bytes = convert.hex2ua(entity['remoteAccount']);

        //Key to Bytes
        for (var k = 0; k < key2bytes.length; ++k) {
            b[e++] = key2bytes[k];
        }
    }

    return new Uint8Array(r, 0, e);
};