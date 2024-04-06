"use strict";
const fetch = require("node-fetch");
const cheerio = require("cheerio");
const aws = require("aws-sdk");
const { URL } = require('url');

const { v4: uuidv4 } = require("uuid");
const { RESPONSE, ERROR } = require("../../utils/response");

const { checkAuthRole } = require("../../middleware/checkAuthRole");

const {
  ENV,
  DNS_API_KEY,
  ACCESS_KEY_ID,
  SECRET_ACCESS_KEY,
  PROFILE_PIC_BUCKET
} = require("../../utils/constants");
const { checkDomainLimit, sharedAccounts } = require("./functions/domain");

const db = require("../../database/db");
const {
  DOMAIN_VERIFICATIONS,
  AUTHORIZATION,
  DOMAIN_TABLE,
  ADDED_USER_TABLE,
  ROLES_TABLE,
  STRIPE_DATA_TABLE,
  SCAN_SETTINGS_TABLE,
  GENERAL_SETTINGS_TABLE,
  WORKFLOW_INTEGRATIONS_TABLE,
  CAMPAIGN_TABLE,
  PLAYBOOK_TABLE
} = require("../../utils/tables");

const domainMethods = ["DNS_TXT", "DNS_CNAME", "FILE", "META"];

module.exports.SwitchDomain = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);

    const targetDomain = event.body.domain;
    const result = await checkAuthRole(event);
    const email = result["email"];
    const getParams = {
      TableName: "Added-User",
      Key: {
        email: email
      }
    };
    const data = await db.get(getParams).promise();
    if (!data.Item) {
      throw Error("No Such User in the Database");
    }
    const domains = data.Item.domain;
    for (const element of domains) {
      if (targetDomain === element) {
        return CALLBACK(
          null,
          RESPONSE(
            {
              message: "Switched to " + targetDomain
            },
            event
          )
        );
      }
    }
    throw Error("You are associated with no such domain");
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

//Get all domains associated with the user
module.exports.GetDomains = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event);
    const email = result["email"];
    const domains = {};
    const rootDomainParams = {
      TableName: DOMAIN_TABLE,
      FilterExpression: "email = :email",
      ExpressionAttributeValues: {
        ":email": email
      }
    };
    const rootDomainsData = await db.scan(rootDomainParams).promise();
    const rootDomains = rootDomainsData.Items;
    rootDomains.forEach((rootDomain) => delete rootDomain["email"]);
    domains["assets"] = rootDomains;

    return CALLBACK(null, RESPONSE(domains, event));
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

const isValidIPv4 = (address) => {
  const ipv4Regex = /^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$/;
  return ipv4Regex.test(address);
};

const isValidIPv6 = (address) => {
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/
  return ipv6Regex.test(address)
}

const isValidDomain = (url) => {
  const domainRegex = /^(?!-)(https?:\/\/)?[A-Za-z0-9-]+([\-\.]{1}[a-z0-9]+)*\.[A-Za-z]{2,6}\/?$/
  return domainRegex.test(url);
};

module.exports.InitiateVerification = async function (
  event,
  context,
  CALLBACK
) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event);
    const email = result["email"];

    const verification = event.body.verificationMethod;
    let identifier = event.body["site"].identifier;
    if (domainMethods.indexOf(verification) === -1) {
      throw Error("The verification method is not known.");
    }
    let responseData = {};

    const getDomainParams = {
      TableName: DOMAIN_TABLE,
      Key: {
        domain: identifier
      }
    };

    const domainData = (await db.get(getDomainParams).promise()).Item;
    if (domainData && domainData.email !== email)
      throw new Error("This domain has already been added by someone else!");
    else if (domainData && domainData.email === email)
      throw new Error("Domain is already added");

    let ip = identifier.split(/\/+/)
    if(ip[0] == "http:" || ip[0] == "https:" && /^\d/.test(ip[1])){
      throw new Error("Please provide a naked ip without http/https")
    }

    const getDomainVerParams = {
      TableName: DOMAIN_VERIFICATIONS,
      Key: {
        email: email
      }
    };

    const domainVerData = (await db.get(getDomainVerParams).promise()).Item;
    let domains = [];
    if (domainVerData) domains = domainVerData.Domains;
    let domain;
    if (domains && domains.find((domain) => domain.name === identifier))
      domain = domains.find((domain) => domain.name === identifier);

    if(isValidDomain(identifier)){
      if(!identifier.includes('http') || !identifier.includes('https')){
        throw new Error("Please provide a valid URL with http/https")
      }
      const res = await fetch(identifier, { method: 'HEAD', redirect: 'manual' })
      if (verification === "META") {
        if (
          !domain ||
          !domain.META ||
          (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
        ) {
          const metaName = "threatspy-site-verification";
          const metaContent = uuidv4();
          let tokenTag = `<meta name="${metaName}" content="${metaContent}">`;
          // tokenTag = tokenTag.replace(/\\"/g, '"');
          console.log(tokenTag);
          if (res.status == 302 || res.status == 307) {
            responseData = {
              method: "META",
              token: tokenTag,
              message: "Please add the received META tag in your site.",
              location: res.headers.get('location')
            };
          } else {
            responseData = {
              method: "META",
              token: tokenTag,
              message: "Please add the received META tag in your site.",
            }
          }
          if (
            !domain ||
            (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
          ) {
            domain = {
              name: identifier,
              META: metaContent,
              createdAt: Date.now(),
              verified: false
            };
          } else if (!domain.META) {
            domain = {
              ...domain,
              META: metaContent,
              verified: false
            };
          }
        } else {
          if (res.status == 302 || res.status == 307) {
            responseData = {
              method: "META",
              token: `<meta name="threatspy-site-verification" content="${domain.META}">`,
              message: "Please add the received META tag in your site.",
              location: res.headers.get('location')
            };
          } else {
            responseData = {
              method: "META",
              token: `<meta name="threatspy-site-verification" content="${domain.META}">`,
              message: "Please add the received META tag in your site."
            };
          }
        }
      } else if (verification === "FILE") {
        if (
          !domain ||
          !domain.FILE ||
          (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
        ) {
          const fileContent_ = uuidv4();
          let fileContent = fileContent_.replace("-", "4f");
          fileContent = fileContent.replace("-", "4f");
          fileContent = fileContent.replace("-", "4f");
          fileContent = fileContent.replace("-", "4f");
  
          const s3 = new aws.S3({
            accessKeyId: ACCESS_KEY_ID,
            secretAccessKey: SECRET_ACCESS_KEY
          });
  
          const key = `threatspy${fileContent}.html`;
          const s3params = {
            Bucket: PROFILE_PIC_BUCKET + "/File-verification",
            Key: key,
            Body: `threatspy${fileContent}.html`,
            ACL: "public-read"
          };
          const uploadData = await s3.upload(s3params).promise();
          console.log(`File uploaded successfully at ${uploadData.Location}`);
  
          if (res.status == 302 || res.status == 307) {
            responseData = {
              method: "FILE",
              token: `threatspy${fileContent}.html`,
              url: `${uploadData.Location}`,
              message: `Please download the file from the given url and put it in your site's root directory.`,
              location: res.headers.get('location')
            };
          } else {
            responseData = {
              method: "FILE",
              token: `threatspy${fileContent}.html`,
              url: `${uploadData.Location}`,
              message: `Please download the file from the given url and put it in your site's root directory.`
            };
          }
  
          if (
            !domain ||
            (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
          ) {
            domain = {
              name: identifier,
              FILE: `threatspy${fileContent}.html`,
              FileLocation: uploadData.Location,
              verified: false
            };
          } else if (!domain.FILE) {
            domain = {
              ...domain,
              FILE: `threatspy${fileContent}.html`,
              FileLocation: uploadData.Location,
              verified: false
            };
          }
        } else {
          if (res.status == 302 || res.status == 307) {
            responseData = {
              method: "FILE",
              token: domain.FILE,
              url: `${domain.FileLocation}`,
              message: `Please download the file from the given url and put it in your site's root directory.`,
              location: res.headers.get('location')
            };
          } else {
            responseData = {
              method: "FILE",
              token: domain.FILE,
              url: `${domain.FileLocation}`,
              message: `Please download the file from the given url and put it in your site's root directory.`,
            }
          }
        }
      } else if (verification === "DNS_TXT") {
        if (
          !domain ||
          !domain.DNS ||
          (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
        ) {
          const metaContent = uuidv4();
          if (res.status == 302 || res.status == 307) {
            responseData = {
              method: "DNS_TXT",
              token: `threatspy-site-verification=${metaContent}`,
              message: "Place the DNS records for your site to verify it.",
              location: res.headers.get('location')
            };
          } else {
            responseData = {
              method: "DNS_TXT",
              token: `threatspy-site-verification=${metaContent}`,
              message: "Place the DNS records for your site to verify it."
            };
          }
  
          if (
            !domain ||
            (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
          ) {
            domain = {
              name: identifier,
              DNS: `${metaContent}`,
              createdAt: Date.now(),
              verified: false
            };
          } else if (!domain.DNS) {
            domain = {
              ...domain,
              DNS: `${metaContent}`,
              verified: false
            };
          }
        } else {
          if (res.status == 302 || res.status == 307) {
            responseData = {
              method: "DNS_TXT",
              token: `threatspy-site-verification=${domain.DNS}`,
              message: "Place the DNS records for your site to verify it.",
              location: res.headers.get('location')
            };
          } else {
            responseData = {
              method: "DNS_TXT",
              token: `threatspy-site-verification=${domain.DNS}`,
              message: "Place the DNS records for your site to verify it.",
            };
          }
        }
      }
    }else if(isValidIPv4(identifier)){
      if (verification === "META") {
        throw new Error(
          "For IP Addresses, FILE Verification method is allowed"
        )
      } else if (verification === "FILE") {
        if (
          !domain ||
          !domain.FILE ||
          (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
        ) {
          const fileContent_ = uuidv4();
          let fileContent = fileContent_.replace("-", "4f");
          fileContent = fileContent.replace("-", "4f");
          fileContent = fileContent.replace("-", "4f");
          fileContent = fileContent.replace("-", "4f");
  
          const s3 = new aws.S3({
            accessKeyId: ACCESS_KEY_ID,
            secretAccessKey: SECRET_ACCESS_KEY
          });
  
          const key = `threatspy${fileContent}.html`;
          const s3params = {
            Bucket: PROFILE_PIC_BUCKET + "/File-verification",
            Key: key,
            Body: `threatspy${fileContent}.html`,
            ACL: "public-read"
          };
          const uploadData = await s3.upload(s3params).promise();
          console.log(`File uploaded successfully at ${uploadData.Location}`);
  
          responseData = {
            method: "FILE",
            token: `threatspy${fileContent}.html`,
            url: `${uploadData.Location}`,
            message: `Please download the file from the given url and put it in your site's root directory.`
          };
  
          if (
            !domain ||
            (Date.now() - domain.createdAt) / (1000 * 60 * 60) >= 48
          ) {
            domain = {
              name: identifier,
              FILE: `threatspy${fileContent}.html`,
              FileLocation: uploadData.Location,
              verified: false
            };
          } else if (!domain.FILE) {
            domain = {
              ...domain,
              FILE: `threatspy${fileContent}.html`,
              FileLocation: uploadData.Location,
              verified: false
            };
          }
        } else {
            responseData = {
              method: "FILE",
              token: domain.FILE,
              url: `${domain.FileLocation}`,
              message: `Please download the file from the given url and put it in your site's root directory.`,
            }
        }
      } else if (verification === "DNS_TXT") {
        throw new Error(
          "For IP Addresses, FILE Verification method is allowed"
        )
      }
    }else{
      if (/^\d/.test(identifier)) {
        if (!isValidIPv4(identifier)) {
          throw new Error("Please provide a valid IPv4 address");
        }else if(!isValidIPv6(identifier)){
          throw new Error("Please provide a valid IPv4 address");
        }
      } else {
        if (!isValidDomain(identifier)) {
          throw new Error("Please provide a valid domain");
        }
      }
    }

    if (domains) {
      domains = domains.filter((domain) => domain.name !== identifier);
      domains.push(domain);
    } else domains = [domain];

    const putParams = {
      TableName: DOMAIN_VERIFICATIONS,
      Item: {
        email: email,
        Domains: domains
      }
    };
    await db.put(putParams).promise();
    return CALLBACK(null, RESPONSE(responseData, event));
  } catch (error) {
    console.log(error);
    if(error.name === 'FetchError' && error.code==='ETIMEDOUT' && error.type === 'system'){
      return CALLBACK(null,RESPONSE({message:"Domain Not Available"},event));
    }
    return CALLBACK(null, ERROR(error, event));
  }
};

//This lambda verifies the ownership of domain/site
module.exports.FinishVerification = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const verification = event.body.verificationMethod;
    let identifier = event.body["site"].identifier;

    const result = await checkAuthRole(event);
    const email = result["email"];

    const getDomainParams = {
      TableName: DOMAIN_TABLE,
      Key: {
        domain: identifier
      }
    };

    const domainData = (await db.get(getDomainParams).promise()).Item;
    if (domainData && domainData.email !== email)
      throw Error("This domain has already been added by someone else!");
    else if (domainData && domainData.email === email)
      throw Error("This domain has already been added by you!");

    if (!identifier.includes("http") && !identifier.includes("https"))
      throw Error(
        "Please provide the protocols. Accepted Protocols are: http/https"
      );

    let arr = identifier.split("/");
    identifier = arr[0] + "//" + arr[1] + arr[2];

    const getDomainVerParams = {
      TableName: DOMAIN_VERIFICATIONS,
      Key: {
        email: email
      }
    };

    const domainVerData = (await db.get(getDomainVerParams).promise()).Item;
    let domains = [];
    if (!domainVerData || !domainVerData.Domains)
      throw Error("Please request for initiate verification first.");
    if (domainVerData) domains = domainVerData.Domains;
    console.log("Domains: " + domains);
    let domain;
    if (domains && domains.find((domain) => domain.name === identifier))
      domain = domains.find((domain) => domain.name === identifier);

    if (domain && domain.verified) {
      return CALLBACK(
        null,
        RESPONSE(
          {
            message: "Domain is already verified!"
          },
          event
        )
      );
    }

    if (
      verification !== "DNS_TXT" &&
      verification !== "FILE" &&
      verification !== "META"
    ) {
      throw Error("No verification data exists for this verification method.");
    }
    if (verification === "META") {
      if (!domain || !domain.META)
        throw Error("Please request for initiate verification first.");
      else if ((Date.now - domain.createdAt) / (1000 * 60 * 60) >= 48)
        throw Error(
          "The Meta tag has expired. Please request for initiate verification again"
        );

      const metaName = "threatspy-site-verification";
      const metaContent = domain.META;
      const response = await fetch(identifier);
      const html = await response.text();
      const $ = cheerio.load(html);
      const siteMetaContent = $(`meta[name="${metaName}"]`).attr("content");
      if (!siteMetaContent || siteMetaContent !== metaContent) {
        throw Error("Failed to verify the ownership of this domain.");
      }
    } else if (verification === "FILE") {
      if (!domain || !domain.FILE)
        throw Error("Please request for initiate verification first.");
      else if ((Date.now - domain.createdAt) / (1000 * 60 * 60) >= 48)
        throw Error(
          "The File token has expired. Please request for initiate verification again"
        );

      const fileData = domain.FILE;
      const tempId = identifier;
      identifier += `/${fileData}`;
      const response = await fetch(identifier);
      if (response.status !== 200) {
        throw Error("Failed to verify the domain.");
      }
      const fileContent = await response.text();
      console.log(fileData);
      console.log(fileContent);
      if (fileContent.trim() !== fileData) {
        throw Error("Failed to verify the domain.");
      }
      identifier = tempId;
    } else if (verification === "DNS_TXT") {
      if (!domain || !domain.DNS)
        throw Error("Please request for initiate verification first.");
      else if ((Date.now - domain.createdAt) / (1000 * 60 * 60) >= 48)
        throw Error(
          "The DNS_TXT token has expired. Please request for initiate verification again"
        );

      const token = "threatspy-site-verification=" + domain.DNS;
      const tempId = identifier;
      if (identifier.includes("https"))
        identifier = identifier.slice("https://".length);
      else if (identifier.includes("http"))
        identifier = identifier.slice("http://".length);
      const dnsVerificationAPI_Url = `https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey=${DNS_API_KEY}&domainName=${identifier}&type=TXT&outputFormat=JSON`;
      console.log(dnsVerificationAPI_Url);
      const response = await (
        await fetch(dnsVerificationAPI_Url, {
          method: "GET"
        })
      ).json();
      const dnsRecords = response.DNSData.dnsRecords;
      console.log(dnsRecords);
      let dnsTxtFound = false;
      for (const dnsRecord of dnsRecords) {
        if (dnsRecord.strings.indexOf(token) !== -1) {
          dnsTxtFound = true;
          break;
        }
      }
      if (!dnsTxtFound) {
        throw Error("Failed to verify the domain.");
      }
      identifier = tempId;
    }

    console.log("Domain: " + Object.entries(domain));
    domain.verified = true;
    if (domains) {
      domains = domains.filter((domain) => domain.name !== identifier);
    }
    domains.push(domain);

    const putVerParams = {
      TableName: DOMAIN_VERIFICATIONS,
      Item: {
        email: email,
        Domains: domains
      }
    };

    await db.put(putVerParams).promise();

    return CALLBACK(
      null,
      RESPONSE(
        {
          message: "Your domain/site has been successfully verified."
        },
        event
      )
    );
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

const isValidUrl = (input) => {
  try {
    new URL(input);
    return true;
  } catch (error) {
    return false;
  }
};

module.exports.AddDomain = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event, "addDomain");

    const email = result["email"];
    await checkDomainLimit(email);
    //await domainLimit(email)
    let domain = event.body.domain;
    const type = event.body.type;
    const scanProfile = event.body.scanProfile;
    const url = event.body.apifile;
    const Authorization = event.body.Authorization;

    if(type !== "API" && type !== "Web Application"){
      throw Error("Please provide a valid type");
    }

    if(type === "API" && !url){
      throw Error("Apifile parameter is missing")
    }

    if(type === "API" && !isValidUrl(url)){
      throw Error("Please provide a valid URL for apifile");
    }
    
    if (!domain || !scanProfile || !type)
      throw Error(
        "Missing atleast one of the required fields - domain, scanProfile or type!"
      );

    if (!domain.includes("http") && !domain.includes("https"))
      throw Error(
        "Please provide the protocols. Accepted Protocols are: http/https"
      );

    let arr = domain.split("/");
    domain = arr[0] + "//" + arr[1] + arr[2];

    if(!Authorization && type === "API"){
      throw Error("Authorization is required for adding domain");
    }

    if (Authorization) {
      //Checking basic errors

      if (!Authorization.Cookie && !Authorization.Token) {
        throw Error("Please include both Cookie and Token in request body.");
      }

      if (Authorization.Cookie) {
        const cookiename = Authorization.Cookie.name;
        const cookievalue = Authorization.Cookie.value;
        if (!cookiename && cookievalue)
          throw Error("Cookie name empty");
        if (cookiename && !cookievalue)
          throw Error("Cookie value empty");
        if(!cookiename && !cookievalue && cookiename !== "" && cookievalue !== ""){
          throw Error("Please provide valid Cookie");
        }
      }
      if (Authorization.Token) {
        const tokenname = Authorization.Token.name;
        const tokenvalue = Authorization.Token.value;
        if (!tokenname && tokenvalue)
          throw Error("Token name empty");
        if (tokenname && !tokenvalue)
          throw Error("Token value empty");
        if(!tokenname && !tokenvalue && tokenname !== "" && tokenvalue !== ""){
          throw Error("Please provide valid Token");
        }
      }

      if(type === "API" && Authorization.Token.name == "" && Authorization.Cookie.name == ""){
        throw Error("Please provide either Cookie or Token for type API");
        }
    }

    const getVerifiedDomainParams = {
      TableName: "Domain-Verifications",
      Key: {
        email: email
      }
    };
    const verDomainData = (await db.get(getVerifiedDomainParams).promise()).Item;
    if (
      !verDomainData ||
      !verDomainData.Domains ||
      !verDomainData.Domains.find((Domain) => Domain.name === domain)
    )
      throw Error("Please request for initiate verification first!");
    else if (
      !verDomainData.Domains.find((Domain) => Domain.name === domain).verified
    )
      throw Error(
        "Domain has not been verified. Please finish verification first!"
      );

    const getDomainParams = {
      TableName: "Domains",
      Key: {
        domain: domain
      }
    };
    const domainData = await db.get(getDomainParams).promise();
    if (domainData.Item) {
      if (domainData.Item.email === email) {
        throw Error("You have already added this domain.");
      } else {
        throw Error("This domain has already been added by someone else.");
      }
    }

    verDomainData.Domains = verDomainData.Domains.filter(
      (Domain) => Domain.name !== domain
    );

    const putDomainVerParams = {
      TableName: DOMAIN_VERIFICATIONS,
      Item: {
        email: email,
        Domains: verDomainData.Domains
      }
    };

    await db.put(putDomainVerParams).promise();

    let appId = uuidv4();
    const appIdParams = {
      TableName: DOMAIN_TABLE,
      FilterExpression: "AppId = :AppId",
      ExpressionAttributeValues: {
        ":AppId": appId
      }
    };
    let appIdData = await db.scan(appIdParams).promise();
    console.log(appIdData.Items.length);
    while (appIdData.Items.length) {
      appId = uuidv4();
      const appIdParams = {
        TableName: DOMAIN_TABLE,
        FilterExpression: "AppId = :AppId",
        ExpressionAttributeValues: {
          ":AppId": appId
        }
      };
      appIdData = await db.scan(appIdParams).promise();
    }
    let domainItem = {
      AppID: appId,
      domain: domain,
      type: type,
      scanProfile: scanProfile,
      email: email
    };

    const putParams = {
      TableName: DOMAIN_TABLE,
      Item: domainItem
    };
    await db.put(putParams).promise();

    if (!event.body.Authorization)
      return CALLBACK(
        null,
        RESPONSE(
          {
            message: "Domain has been added with this scan profile.",
            App_Id: appId
          },
          event
        )
      );
    const domainAuthParams = {
      TableName: AUTHORIZATION,
      Key: {
        email: email
      }
    };

    const domainAuthData = await db.get(domainAuthParams).promise();
    const domainAuth = domainAuthData.Item;
    const Domain = {
      Cookie: {
        name: Authorization.Cookie.name,
        value: Authorization.Cookie.value
      },
      Dname: domain,
      Token: {
        name: Authorization.Token.name,
        value: Authorization.Token.value
      }
    };

    if (!domainAuth) {
      const Domains = [Domain];
      const putDomainAuthParams = {
        TableName: AUTHORIZATION,
        Item: {
          email: email,
          Domains: Domains
        }
      };
      await db.put(putDomainAuthParams).promise();
    } else {
      let Domains = domainAuth.Domains;
      Domains.push(Domain);
      const putDomainAuthParams = {
        TableName: AUTHORIZATION,
        Item: {
          email: email,
          Domains: Domains
        }
      };
      await db.put(putDomainAuthParams).promise();
    }

    return CALLBACK(
      null,
      RESPONSE(
        {
          message: "Domain has been added with this scan profile.",
          App_Id: appId
        },
        event
      )
    );
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

module.exports.DeleteDomain = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const domain = event.body.domain;

    // console.log(domain);

    if (domain === "http://dummy.threatspy.com") {
      // console.log("hit");
      const result = await checkAuthRole(event, "deleteDomain");
      const email = result["email"];

      const params = {
        TableName: STRIPE_DATA_TABLE,
        Key: {
          email: email
        }
      };
      const subscriptionData = await db.get(params).promise();

      // console.log(subscriptionData);

      if (subscriptionData.Item.sampleData === false) {
        throw new Error("Already deleted sample data");
      }

      const customerId = subscriptionData.Item.customerId;

      const putParams = {
        TableName: STRIPE_DATA_TABLE,
        Item: {
          email: email,
          customerId: customerId,
          sampleData: false
        }
      };
      await db.put(putParams).promise();

      return CALLBACK(
        null,
        RESPONSE(
          {
            status: "Success",
            message: "Sample Data deleted successfully"
          },
          event
        )
      );
    } else {
      const result = await checkAuthRole(event);
      const email = result["email"];

      const domainParams = {
        TableName: DOMAIN_TABLE,
        Key: {
          domain: domain
        }
      };
      const domainData = await db.get(domainParams).promise();
      if (!domainData.Item) {
        throw Error("This domain does not exist.");
      }
      const domainOwner = domainData.Item.email;
      if (domainOwner !== email) {
        throw Error(
          "You do not have the required permission to perform this action."
        );
      }

      const deleteDomParams = {
        TableName: DOMAIN_TABLE,
        Key: {
          domain: domain
        }
      };
      await db.delete(deleteDomParams).promise();


      const deleteScanSettingsParams = {
        TableName: SCAN_SETTINGS_TABLE,
        Key: {
          email: email
        }
      };
      let profile = (await db.get(deleteScanSettingsParams).promise()).Item
      const scandomain = Object.keys(profile.profiles);
      const matchingSDomain = scandomain.find((gd) => gd === domain);
      if (matchingSDomain) {
        delete profile.profiles[matchingSDomain];
        const updateScanSettingsParams = {
          TableName: SCAN_SETTINGS_TABLE,
          Key: {
            email: email,
          },
          UpdateExpression: 'SET profiles = :profiles',
          ExpressionAttributeValues: {
            ':profiles': profile.profiles,
          },
        };
        await db.update(updateScanSettingsParams).promise();
      } else {
        console.log('Domain does not match. No deletion performed.');
      }

      const deleteGeneralSettingsParams = {
        TableName: GENERAL_SETTINGS_TABLE,
        Key: {
          email: email
        }
      };
      let gprofile = (await db.get(deleteGeneralSettingsParams).promise()).Item
      const generalDomain = Object.keys(gprofile.profiles);
      const matchingGDomain = generalDomain.find((gd) => gd === domain);
      if (matchingGDomain) {
        delete gprofile.profiles[matchingGDomain];
        const updateGeneralSettingsParams = {
          TableName: GENERAL_SETTINGS_TABLE,
          Key: {
            email: email,
          },
          UpdateExpression: 'SET profiles = :profiles',
          ExpressionAttributeValues: {
            ':profiles': gprofile.profiles,
          },
        };
        await db.update(updateGeneralSettingsParams).promise();
      } else {
        console.log('Domain does not match. No deletion performed.');
      }

      const deleteAuthorizationSettingsParams = {
        TableName: AUTHORIZATION,
        Key: {
          email: email,
        },
      };
      let authprofile = (await db.get(deleteAuthorizationSettingsParams).promise()).Item;
      const authdomain = authprofile.Domains.filter((dom) => dom.Dname === domain);
      if (authdomain.length > 0) {
        const indexToRemove = authprofile.Domains.indexOf(authdomain[0]);
        if (indexToRemove !== -1) {
          authprofile.Domains.splice(indexToRemove, 1);
          const updateAuthorizationSettingsParams = {
            TableName: AUTHORIZATION,
            Key: {
              email: email,
            },
            UpdateExpression: 'SET Domains = :Domains',
            ExpressionAttributeValues: {
              ':Domains': authprofile.Domains,
            },
          };
          await db.update(updateAuthorizationSettingsParams).promise();
        }
      }

      const deleteIntegration = {
        TableName: WORKFLOW_INTEGRATIONS_TABLE,
        Key: {
          domain: domain
        }
      };
      await db.delete(deleteIntegration).promise();


      //Campaign
      //Table:- CAMPAIGN_TABLE, Key:- email, ChildKey:- domain
      const deleteCampaign = {
        TableName: CAMPAIGN_TABLE,
        Key: {
          email: email
        }
      };
      let integration = (await db.get(deleteCampaign).promise()).Item
      const intdomain = integration.campaigns.filter((dom) => dom.domain === domain);
      console.log(intdomain)
      if (intdomain.length > 0) {
        const indexToRemove = integration.campaigns.indexOf(intdomain[0]);
        if (indexToRemove !== -1) {
          integration.campaigns.splice(indexToRemove, 1);
          const updateCampaignSettingsParams = {
            TableName: CAMPAIGN_TABLE,
            Key: {
              email: email,
            },
            UpdateExpression: 'SET campaigns = :campaigns',
            ExpressionAttributeValues: {
              ':campaigns': integration.campaigns,
            },
          };
          await db.update(updateCampaignSettingsParams).promise();
        }
      }
      //Playbook
      //Table:- PLAYBOOK_TABLE, Key:- email, ChildKey:- domain
      const getPlaybookParams = {
        TableName: PLAYBOOK_TABLE,
        KeyConditionExpression: "email = :email",
        ExpressionAttributeValues: {
          ":email": email
        }
      };
      const playbookData = (await db.query(getPlaybookParams).promise()).Items;
      const playbookDataToDelete = playbookData.filter(item => item.domain === domain);
      const deletePromises = playbookDataToDelete.map(playbook => {
        const deleteParams = {
          TableName: PLAYBOOK_TABLE,
          Key: {
            email: playbook.email,
            playbook_id: playbook.playbook_id
          }
        };
        return db.delete(deleteParams).promise();
      });
      await Promise.all(deletePromises);

      return CALLBACK(
        null,
        RESPONSE(
          { status: "Success", message: "Domain deleted successfully" },
          event
        )
      );
    }
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

//Get all shared accounts for a user with atleast one asset of their own
module.exports.GetSharedAccounts = async (event, content, CALLBACK) => {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);
    const result = await checkAuthRole(event);
    const email = result["email"];
    const rootMail = result["rootMail"]
    const accounts = await sharedAccounts(email);
    const responseData = {
      rootUser: rootMail,
      childUsers : accounts.childUsers
    }
    return CALLBACK(null, RESPONSE(responseData, event));
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};

module.exports.SwitchAccounts = async function (event, context, CALLBACK) {
  try {
    if (ENV !== "DEV") event.body = JSON.parse(event.body);

    const targetEmail = event.body.email;
    const result = await checkAuthRole(event);
    const email = result["email"];

    const allPermissionsParams = {
      TableName: ROLES_TABLE,
      Key: {
        role: "Admin"
      }
    };

    const allPermissionsData = await db.get(allPermissionsParams).promise();
    const allPermissions = allPermissionsData.Item.permissions;
    if (targetEmail === email)
      return CALLBACK(
        null,
        RESPONSE(
          {
            message: "Switched to root account - " + targetEmail,
            role: "Admin",
            permissions: allPermissions
          },
          event
        )
      );
    const accounts = await sharedAccounts(email);

    if (targetEmail === result['rootMail']) {
      return CALLBACK(
        null,
        RESPONSE(
          {
            message: "Switched to root account - " + targetEmail,
            role: "Admin",
            permissions: allPermissions
          },
          event
        )
      );
    }

    for (const sharedAccount of accounts["childUsers"]) {
      if (targetEmail === sharedAccount.email) {
        const getRoleParams = {
          TableName: ADDED_USER_TABLE,
          Key: {
            email: email
          }
        };

        const roleData = await db.get(getRoleParams).promise();
        const role = roleData.Item.ChildUsers.find(
          (user) => user.email === targetEmail
        ).role;
        const getPermissionParams = {
          TableName: ROLES_TABLE,
          Key: {
            role: role
          }
        };
        const permissionData = await db.get(getPermissionParams).promise();
        const permissions = permissionData.Item.permissions;
        return CALLBACK(
          null,
          RESPONSE(
            {
              message: "Switched to " + targetEmail,
              childUserEmail: targetEmail,
              role: role,
              permissions: permissions
            },
            event
          )
        );
      }
    }
    throw Error("You are not associated with any such account");
  } catch (error) {
    console.log(error);
    return CALLBACK(null, ERROR(error, event));
  }
};
