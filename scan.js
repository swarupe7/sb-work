"use strict";
const { RESPONSE, ERROR } = require("../../utils/response");
const { ENV } = require("../../utils/constants");
const { getScanSettings, editScanSettings } = require("./functions/scan");
const {
  checkIntegrationPermissionForUser
} = require("../../utils/integration");
const { checkAuthRole } = require("../../middleware/checkAuthRole");
const { GetDomains } = require("../domain/domainHandler");

module.exports.ScanSettings = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event);
    const email = result["email"];

    const domain = event.body.domain;
    if (!domain) throw Error("Missing field domain");
    await checkIntegrationPermissionForUser(email, domain, "GetScanSettings");
    const data = await getScanSettings(email, domain);
    return CALLBACK(null, RESPONSE({ data: data }, event));
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

module.exports.EditScanSettings = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event, "edit-scan-settings");
    const email = result["email"];
    const domain = event.body.domain;
    if (!domain) throw Error("Missing field domain");
    if(!event.body.OWASP){
      throw Error("Missing OWASP field");
    }
    if (event.body.scan_common_ports) {
      if (event.body.ports_avoid.length || event.body.ports_include.length)
        throw Error(
          "Ports_avoid and Ports_include accepted only if scan_common_ports is false"
        );
    }

    const DomainType = await new Promise((resolve, reject) => {
      GetDomains(event, null, (err, response) => {
        if (err) reject(err);
        else resolve(response);
      });
    });

    let Domainassets=()=>{ return DomainType.assets.filter(asset=>asset.domain === domain)[0] || null }

    if(Domainassets()=== null){
      throw Error("Add assets to this Domain")
    }
    
    const getDomainType = Domainassets().type;
    if (getDomainType === "Web Application") {
      const valuesPossibleOWASP = ["2021", "2017", "Both"];
      if (!valuesPossibleOWASP.includes(event.body.OWASP))
        throw Error("Invalid OWASP value! Possible values are: 2021,2017,Both");     
    }

    if(getDomainType === "API"){

      if(event.body.OWASP !== "2023"){
        throw Error("Invalid OWASP value! Possible value is: 2023");  
      }

      if(event.body.api_file===undefined){
        throw Error("Missing api_file field");
      }
      if(event.body.api_file===""){
        throw Error("Missing api_file value");
      }


    }
    const data = await editScanSettings(event.body, email, domain);
    return CALLBACK(
      null,
      RESPONSE(
        { message: "Updated Scan Settings successfully.", data: data },
        event
      )
    );
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};
