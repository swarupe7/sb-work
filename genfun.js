const {
  GENERAL_SETTINGS_TABLE,
  DOMAIN_TABLE
} = require("../../../utils/tables");
const db = require("../../../database/db");

module.exports.getProfile = async function (email, domain) {
  try {
    const domainParams = {
      TableName: DOMAIN_TABLE,
      Key: {
        domain: domain
      }
    };
    const domainData = await db.get(domainParams).promise();
    if (domainData.Item=== undefined) {
     return null;
    }

    const scanProfile = domainData.Item.scanProfile;
    const params = {
      TableName: GENERAL_SETTINGS_TABLE,
      Key: {
        email: email
      }
    };
    const data = await db.get(params).promise();
    if (!data.Item) {
      const newItem = {
        email: email,
        profiles: {
          [domain]: {
            scan: "Manual",
            scanType: {
              scheduleScan: false,
              nextScan: "",
              recurringScan: true,
              frequency: "7 Days"
            }
          }
        }
      };
      const paramsPut = {
        TableName: GENERAL_SETTINGS_TABLE,
        Item: newItem
      };
      await db.put(paramsPut).promise();
      return {
        domain: domain,
        scanProfile: scanProfile,
        ...newItem["profiles"][domain]
      };
    }
    return {
      domain: domain,
      scanProfile: scanProfile,
      ...data.Item["profiles"][domain]
    };
  } catch (error) {
    console.log(error);
    throw Error(error.message);
  }
};

module.exports.editProfile = async function (email, domain, data) {
  try {
    if (data.scan === "Automatic") {
      if (!data.scanType) throw Error('Field "scanType" is required.');
      if (
        data.scanType.scheduleScan &&
        (!data.scanType.nextScan || data.scanType.nextScan === "")
      )
        throw Error('Field "nextScan" is required.');
      if (
        data.scanType.recurringScan &&
        (!data.scanType.frequency || data.scanType.frequency === "")
      )
        throw Error('Field "frequency" is required.');
      if (!data.scanType.type) data.scanType.type = ""
    }
    const scanProfile = data.scanProfile;
    if (scanProfile) {
      const domainParams = {
        TableName: DOMAIN_TABLE,
        Key: {
          domain: domain
        }
      };
      const domainData = await db.get(domainParams).promise();
      if (!domainData.Item) throw Error("The domain is not added!");
      const updatedDomainData = { ...domainData.Item, scanProfile };
      const putDomainParams = {
        TableName: DOMAIN_TABLE,
        Item: {
          ...updatedDomainData
        }
      };
      await db.put(putDomainParams).promise();
    }
    const getParams = {
      TableName: GENERAL_SETTINGS_TABLE,
      Key: {
        email: email
      }
    };
    const newSetting = {
      scan: data.scan ? data.scan : currentSettings.scan,
      scanType: data.scanType
        ? data.scanType
        : {
            scheduleScan: false,
            nextScan: "",
            recurringScan: true,
            frequency: "7 Days"
          }
    };
    const profileData = await db.get(getParams).promise();
    if (!profileData.Item) {
      const newItem = {
        email: email,
        profiles: {
          [domain]: newSetting
        }
      };
      const paramsPut = {
        TableName: GENERAL_SETTINGS_TABLE,
        Item: newItem
      };
      await db.put(paramsPut).promise();
      return { domain, scanProfile, ...newSetting };
    } else {
      let allProfiles = profileData.Item["profiles"];
      const currentSettings = allProfiles[domain];
      const updatedSettings = {
        scan: data.scan ? data.scan : currentSettings.scan,
        scanType: data.scanType ? data.scanType : currentSettings.scanType
      };
      delete allProfiles[domain];
      const params = {
        TableName: GENERAL_SETTINGS_TABLE,
        Item: {
          email: email,
          profiles: {
            ...allProfiles,
            [domain]: updatedSettings
          }
        }
      };
      await db.put(params).promise();
      if(data.scan == "Manual"){
        return { domain, scanProfile, scan: updatedSettings.scan };
      }
      return { domain, scanProfile, ...updatedSettings };
    }
  } catch (error) {
    console.log(error);
    throw Error(error.message);
  }
};
