"use strict";
const { RESPONSE, ERROR } = require("../../utils/response");
const { ENV } = require("../../utils/constants");
const { getProfile, editProfile } = require("./functions/general");
const { checkAuthRole } = require("../../middleware/checkAuthRole");

module.exports.GetGeneralSettings = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event, "GetGeneralSettings");
    const email =result["email"];
    const domain = event.body.domain;
    if (!domain) throw Error("Missing field domain");
    const data = await getProfile(email, domain);
    if (!data)  return CALLBACK(null, RESPONSE({ message: "No profile available" }, event));
    return CALLBACK(null, RESPONSE({ data: data }, event));
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

//maunal is passed, ignore scanType is ignored. Don't pass it in response.
module.exports.EditGeneralSettings = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event, "EditGeneralSettings");
    const email = result["email"];
    const domain = event.body.domain;
    if (!domain) throw Error("Missing field domain");
    // if (
    //   event.body.scan === "Manual" &&
    //   (event.body.scanType.recurringScan ||
    //     event.body.scanType.scheduleScan ||
    //     event.body.scanType.frequency.length ||
    //     event.body.scanType.nextScan.length || event.body.scanType.type)
    // ){
    //   CALLBACK(
    //     null,
    //     RESPONSE(
    //       { message: "Scan is Manual. Hence, scanType fields ignored!"},
    //       event
    //     )
    //   );
    // }
    if (
      event.body.scanType.recurringScan &&
      !event.body.scanType.frequency.length
    )
      throw Error("No frequency provided!");
    else if (
      !event.body.scanType.recurringScan &&
      event.body.scanType.frequency.length
    )
      throw Error("Frequency ignored since recurringScan is false!");
    if (
      event.body.scanType.scheduleScan &&
      !event.body.scanType.nextScan.length
    )
      throw Error("NextScan field needs to be provided!");
    else if (
      !event.body.scanType.scheduleScan &&
      event.body.scanType.nextScan.length
    )
      throw Error("NextScan ignored since scheduleScan is false!");
    if (!event.body.scanType.type) event.body.scanType.type = ""
    const data = await editProfile(email, domain, event.body);
    return CALLBACK(
      null,
      RESPONSE(
        { message: "General Settings updated successfully.", data: data },
        event
      )
    );
    
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};
