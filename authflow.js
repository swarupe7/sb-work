"use strict";
const db = require("../../database/db");
const { ENV } = require("../../utils/constants");
const { AUTHORIZATION } = require("../../utils/tables");
const { RESPONSE, ERROR } = require("../../utils/response");
const { checkAuthRole } = require("../../middleware/checkAuthRole");
const { GetSubscriptionStatus }=require("../../src/subscription/subscriptionHandler");


module.exports.AddTokenCookies = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    let TokenFlag = false;
    let CookieFlag = false;


    const result = await checkAuthRole(event,"addTokenCookies");
    const email = result["email"];

    if(!event.body.Authorization){
      throw Error("Missing field Authorization")
    }

    if(event.body.Authorization.Domain===undefined){
      throw Error("Missing field Domain");
    }
    if(event.body.Authorization.Domain ===""){
      throw Error("Missing value for Domain")
    }
    
    const arr = event.body.Authorization.Domain.split("/");
    let dname = "";
    if (event.body.Authorization.Domain.includes("http"))
      dname = arr[0] + "//" + arr[2];
    else dname = arr[0];
         
    const subscriptionStatus = await new Promise((resolve, reject) => {
      GetSubscriptionStatus(event, null, (err, response) => {
        if (err) reject(err);
        else resolve(response);
      });
    });
  
    const subscriptionType = subscriptionStatus.subscription_type;

    // Check if the plan is a trial plan
   

    let cookiename ;
    let cookievalue;
    let tokenname;
    let tokenvalue;

  

    if(event.body.Authorization.Cookie!==undefined && (event.body.Authorization.Cookie.name!=='' || event.body.Authorization.Cookie.value!==''))
       { cookiename= event.body.Authorization.Cookie.name;
     cookievalue = event.body.Authorization.Cookie.value;
     CookieFlag=true;}
     if(event.body.Authorization.Token!==undefined && (event.body.Authorization.Token.name!=='' || event.body.Authorization.Token.value!=='')){
     tokenname = event.body.Authorization.Token.name;
     tokenvalue = event.body.Authorization.Token.value;
     TokenFlag=true;}
   
     //Checking basic errors

     if (subscriptionType === "Trial Plan" && TokenFlag && CookieFlag) {
      return CALLBACK(null, ERROR({ message: "Adding Token/Cookie not allowed in Trial Plan" }, event));
    }
    if (subscriptionType === "Trial Plan" && TokenFlag ) {
      return CALLBACK(null, ERROR({ message: "Adding Token not allowed in Trial Plan" }, event));
    }
    if (subscriptionType === "Trial Plan" && CookieFlag) {
      return CALLBACK(null, ERROR({ message: "Adding Cookie not allowed in Trial Plan" }, event));
    }

     if ( event.body.Authorization.Token!==undefined && !tokenname && !tokenvalue) 
     throw Error("Token name and value are empty");
     if ( event.body.Authorization.Cookie!==undefined && !cookiename && !cookievalue)
     throw Error("Cookie name and value are empty");

    if (event.body.Authorization.Token!==undefined && !tokenname) 
      throw Error("Token name empty");
    if (event.body.Authorization.Token!==undefined &&  !tokenvalue) 
      throw Error("Token value empty");
    if (event.body.Authorization.Cookie!==undefined && !cookiename) 
      throw Error("Cookie name empty");
    if (event.body.Authorization.Cookie!==undefined && !cookievalue) 
      throw Error("Cookie value empty");

    const getParams = {
      TableName: AUTHORIZATION,
      Key: {
        email: email
      }
    };

    const data = await db.get(getParams).promise();

    if (!data.Item || !data.Item.Domains) {
      const Domain = {
        Dname: dname,
        Cookie: cookiename && cookievalue ? { name: cookiename, value: cookievalue } : undefined,
        Token: tokenname && tokenvalue ? { name: tokenname, value: tokenvalue } : undefined
      };
      const Domains = [Domain];
      const putParams = {
        TableName: AUTHORIZATION,
        Item: {
          email: email,
          Domains: Domains
        }
      };
      await db.put(putParams).promise();
    } else if (!data.Item.Domains.find((domain) => domain.Dname === dname)) {
      const Domain = {
        Dname: dname,
        Cookie: cookiename && cookievalue ? { name: cookiename, value: cookievalue } : undefined,
        Token: tokenname && tokenvalue ? { name: tokenname, value: tokenvalue } : undefined
      };
      let Domains = data.Item.Domains;
      Domains.push(Domain);
      const putParams = {
        TableName: AUTHORIZATION,
        Item: {
          email: email,
          Domains: Domains
        }
      };
      await db.put(putParams).promise();
    } else {
      const Domain = data.Item.Domains.find((domain) => domain.Dname === dname);

      if (tokenname && tokenvalue) {
        if (Domain.Token !== undefined) {
          Domain.Token.name = tokenname;
          Domain.Token.value = tokenvalue;
        } else {
          Domain.Token = {
            name: tokenname,
            value: tokenvalue
          };
        }
        TokenFlag = true;
      } else {
        if(Domain.Token !==undefined && Domain.Token.name===''){
          delete Domain.Token;
        }
      }
      if (cookiename && cookievalue) {
        if (Domain.Cookie !== undefined) {
          Domain.Cookie.name = cookiename;
          Domain.Cookie.value = cookievalue;
        } else {
          Domain.Cookie = {
            name: cookiename,
            value: cookievalue
          };
        }
        CookieFlag = true;
      } else {
        if(Domain.Cookie !==undefined && Domain.Cookie.name===''){
        delete Domain.Cookie;}
      }

      let Domains = data.Item.Domains;
      Domains = Domains.filter((domain) => domain.Dname !== dname);

      if ((Domain.Token === undefined || Domain.Token.name === undefined || Domain.Token.value === undefined) && 
          (Domain.Cookie === undefined || Domain.Cookie.name === undefined || Domain.Cookie.value === undefined)) {
        return CALLBACK(null, ERROR({ message: "Missing value for Token/Cookie" }, event));
      }


      Domains.push(Domain);
      const putParams = {
        TableName: AUTHORIZATION,
        Item: {
          email: email,
          Domains: Domains
        }
      };
      await db.put(putParams).promise();
    }

    let responseData;

    if (TokenFlag && CookieFlag) {
      responseData = {
        message: "Token and cookie are added to the domain."
      };
    } else if (TokenFlag) {
      responseData = {
        message: "Token is added to the domain."
      };
    } else if (CookieFlag) {
      responseData = {
        message: "Cookie is added to the domain."
      };
    } else {
      responseData = {
        message: "Missing value for Token/Cookie"
      };
    }

    return CALLBACK(null, RESPONSE(responseData, event));
  } catch (error) {
    return CALLBACK(null, ERROR(error, event));
  }
};

module.exports.DeleteTokenCookies = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);

    if(!event.body.Domain){
      throw Error("Missing field Domain");
    }

    if(!event.body.type){
      throw Error("Missing field Type");
    }

    const result = await checkAuthRole(event,"deleteTokenCookies");
    const email = result["email"];
    const type = event.body.type;
    const arr = event.body.Domain.split("/");
    const dname = arr[0] + "//" + arr[2];

    

    const getParams = {
      TableName: AUTHORIZATION,
      Key: {
        email: email
      }
    };
    const data = await db.get(getParams).promise();

    let responseData;
    if (
      !data.Item ||
      !data.Item.Domains ||
      data.Item.Domains.find((domain) => domain.Dname === dname) === undefined
    ) {
      throw Error("No token and cookie associated with this domain!");
    } else {
      if (type === "Cookie") {
        let Domains = data.Item.Domains;
        let domain = Domains.find((domain) => domain.Dname === dname);
        if (!domain.Cookie)
          throw Error("Cookie doesn't exist for this domain");
        delete domain["Cookie"];
        Domains = Domains.filter((domain) => domain.Dname !== dname);
        if (domain.Token) Domains.push(domain);
        const putParams = {
          TableName: AUTHORIZATION,
          Item: {
            email: email,
            Domains: Domains
          }
        };
        await db.put(putParams).promise();
        responseData = {
          message: "Deleted the cookie of this domain."
        };
      } else if (type === "Token") {
        let Domains = data.Item.Domains;
        let domain = Domains.find((domain) => domain.Dname === dname);
        if (!domain.Token) throw Error("Token doesn't exist for this domain");
        delete domain["Token"];
        Domains = Domains.filter((domain) => domain.Dname !== dname);
        if (domain.Cookie) Domains.push(domain);
        const putParams = {
          TableName: AUTHORIZATION,
          Item: {
            email: email,
            Domains: Domains
          }
        };
        await db.put(putParams).promise();
        responseData = {
          message: " Deleted the Token of this domain."
        };
      } else throw Error("Invalid type!");
    }
    return CALLBACK(null, RESPONSE(responseData, event));
  } catch (error) {
    return CALLBACK(null, ERROR(error, event));
  }
};

//Get All Authorizations
module.exports.GetTokenCookies = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);

    const result = await checkAuthRole(event);
    const email = result["email"];

    if(!event.body.domain){
      throw Error("Missing field Domain");
    }

    if(!event.body.domain || event.body.domain.length === 0){
      return CALLBACK(null, ERROR({message:"Please enter a domain associated to your account"},event))
    }

    const getParams = {
      TableName: AUTHORIZATION,
      Key: {
        email: email
      }
    };

    const data = await db.get(getParams).promise();
    if (!data.Item || !data.Item.Domains || !data.Item.Domains.length) {
      throw Error("No token and cookie associated with any domain!");
    }

    const domainData = data.Item.Domains.find(domain => domain.Dname === event.body.domain);

     if (!domainData){
      //  || !domainData.Token || !domainData.Cookie) {
     const errorMessage = 'No token and cookie associated with this domain';
      return CALLBACK({ status: "Success", message: errorMessage  });
    }

    const responseData = {
      data: domainData
    };
    
    if(responseData.data.Cookie===undefined && responseData.data.Token===undefined){
      const errorMessage = { status:"No Content",message:'No token and cookie associated with this domain'};
      return CALLBACK(null,RESPONSE(errorMessage,event));
    }
    return CALLBACK(null, RESPONSE(responseData, event));
  } catch (error) {
    
    return CALLBACK(null, ERROR(error, event));
  }
};
