((require, process, module) => {
    "use strict"; // ECMAScript 5's strict mode

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Libraries
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    const
        util = require('util'),
        compression = require('compression'),
        express = require('express'),
        bodyParser = require('body-parser'),
        moment = require('moment'),
        logentries = require('le_node'),
        request = require('request'),
        http = require('http'),
        https = require('https'),
        requestretry = require('requestretry'),
        deAsync = require('deasync'),
        fs = require('fs');

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Configuration from env vars
    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // defaults
    const defaults = {
        _endpoint_name: '',
        _app_name: '',
        _pod_id: '',
        _environment : '',
        _local_deployment: 'false',
        _debug: 'true',
        _webservices_port : '10000',
        _token : '',
        _profile : 'default',
        _endpoints_services_api : 'https://endpoints-services/api',
        USE_SSL: false,
        SSL_KEY: '',
        SSL_CERT: '',
        _custom_domain : '',
        _base_domain : 'localhost:8000',
        LOGENTRIES_TOKEN : '',
        _endpoint_config : {}
    };

    const settings = Object.assign({}, defaults, process.env);
    const {
        // Endpoint constants
        _endpoint_name:     endpointName,
        _app_name:          applicationName,
        _pod_id:            _podId,
        _environment:       environment,
        _local_deployment:  _localDeployment,
        _debug:             _debug,
        // HTTP services properties
        _webservices_port:  webServicesPort,
        _token:             token,
        _profile:           profile,
        _endpoints_services_api:    endpointsServicesApi,
        USE_SSL:            _useSsl,
        SSL_KEY:            sslKey,
        SSL_CERT:           sslCert,
        // System properties
        _custom_domain:     domainCustom,
        _base_domain:       domainBase,
        LOGENTRIES_TOKEN:   logentriesToken,
        // Endpoint specific properties
        _endpoint_config:   _endpoint_config
    } = settings;

    const podId = _podId.length > 5 ? _podId.substring(_podId.length-5): _podId;
    const localDeployment = _localDeployment !== 'false' && !!_localDeployment;
    const debug = _debug !== 'false' && !!_debug;
    const useSsl = !localDeployment || _useSsl;

    // Endpoint specific properties
    const endpointDefaults = {
        username: '',
        password: ''
    };
    const endpointConfig =  Object.assign({}, endpointDefaults, JSON.parse(_endpoint_config));
    const { username, password } = endpointConfig;

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Logger configuration
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    const logentriesLogger = logentriesToken ? new logentries({
        token: logentriesToken,
        timestamp: false,
        withLevel: false,
        console: false
    }) : null;

    const logLocalFormat = (level, message) =>
        moment().format('MM-DD HH:mm:ss.SSS') +
        ' [' + level + ' '.repeat(5 - level.length) + '] ' +
        message;

    const logLogentriesFormat = (level, message) =>
        moment().format('YYYY-MM-DD HH:mm:ss.SSS ZZ') + ' comp=endpoint ' +
        'level=' + level + ' ' +
        'podId=' + podId + ' ' +
        'app=' + applicationName + ' ' +
        'endpoint=' + endpointName + ' ' +
        'env=' + environment + ' ' +
        message;


    const logDebug = message => {
        if (message && debug) {
            console.log(logLocalFormat('DEBUG', message));
            if (logentriesLogger) {
                logentriesLogger.debug(logLogentriesFormat('DEBUG', message))
            }
        }
    };

    const logInfo = message => {
        if (message) {
            console.info(logLocalFormat('INFO', message));
            if (logentriesLogger) {
                logentriesLogger.info(logLogentriesFormat('INFO', message))
            }
        }
    };

    const logWarn = message => {
        if (message) {
            console.warn(logLocalFormat('WARN', message));
            if (logentriesLogger) {
                logentriesLogger.warning(logLogentriesFormat('WARN', message))
            }
        }
    };

    const logError = message => {
        if (message) {
            console.error(logLocalFormat('ERROR', message));
            if (logentriesLogger) {
                logentriesLogger.err(logLogentriesFormat('ERROR', message))
            }
        }
    };

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Basic configuration
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    const maskToken = token => {
        if(!token){
            return '-';
        }
        return token.length < 10 ? '.'.repeat(token.length) :
            token.length < 20 ? token.substr(0, 2) + '.'.repeat(token.length - 4) + token.substr(token.length - 2) :
            token.substr(0, 4) + '.'.repeat(token.length - 8) + token.substr(token.length - 4)
    };

    const maskedToken = maskToken(token);

    let cDomain = domainCustom;
    if (cDomain) {
        cDomain = (localDeployment ? 'http' : 'https') + '://' + cDomain
    } else {
        cDomain = (localDeployment ? 'http' : 'https') + '://' + applicationName + '.' + domainBase + '/' + environment
    }
    const domain = cDomain.toLowerCase();
    const secondaryDomain = ((localDeployment ? 'http' : 'https') + '://' + domainBase + '/' + applicationName + '/' + environment).toLowerCase();

    const webhookUrl = domain + '/endpoints/' + endpointName;

    const maskedLogentriesToken = maskToken(logentriesToken);
    const proto = useSsl ? 'https' : 'http';
    logInfo('Configured endpoint [' + endpointName + ']: '+
        proto + ' [0.0.0.0:' + webServicesPort + '], '+
        'webhook [' + webhookUrl + '], '+
        'token [' + maskedToken + '], '+
        'logentries [' + maskedLogentriesToken + ']'+
        (localDeployment ? ', local deployment' : '')
    );

    logInfo('Configured Endpoint Services - api ['+endpointsServicesApi+']');

    const maskedPassword = maskToken(password);
    logInfo('Configured Watson (Tone Analyzer) endpoint: username [' + username + '], password [' + maskedPassword + ']');

    const convertException = (err, code) => {
        if (!err) {
            return {
                __endpoint_exception__: true,
                message: 'There is an issue on the endpoint',
                error: !code ? {code: 'general', name: 'General exception'} : code
            }
        } else {
            if (typeof err === 'string') {
                return {
                    __endpoint_exception__: true,
                    message: err,
                    error: !code ? {code: 'general', name: 'General exception'} : code
                }
            } else if (err.__endpoint_exception__) {
                return err
            } else if (err.message) {
                return {
                    __endpoint_exception__: true,
                    message: err.message,
                    additionalInfo: err,
                    error: !code ? {code: 'general', name: 'General exception'} : code
                }
            } else {
                return {
                    __endpoint_exception__: true,
                    message: 'There is an issue on the endpoint',
                    additionalInfo: err,
                    error: !code ? {code: 'general', name: 'General exception'} : code
                }
            }
        }
    };

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // node.js related events
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    process.on('exit', code => logInfo('Endpoint stopped - exit code ['+ code+']'));
    process.on('SIGINT', () => {
        logInfo('Endpoint stopped');
        process.exit(0)
    });
    process.on('beforeExit', code => logInfo('Stopping endpoint - exit code ['+ code+']'));
    process.on('warning', warning => logWarn('Warning ['+util.inspect(warning, { showHidden: true, depth: null })+']'));

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Endpoints services
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    const esExecutePost = (path, body) => {
        let options = {
            url: endpointsServicesApi + path,
            headers: {
                token: token,
                version: 'v1'
            },
            json: true,
            body: body,
            agentOptions: {
                rejectUnauthorized: false // trust all certs
            },

            // The below parameters are specific to request-retry
            maxAttempts: 10,   // (default) try 5 times
            retryDelay: 5000,  // (default) wait for 5s before trying again
            retryStrategy: requestretry.RetryStrategies.HTTPOrNetworkError // (default) retry on 5xx or network errors
        };

        return requestretry.post(options)
            .then(response => response.body)
    };

    // app log (POST /api/endpoints/logs)
    const sendAppLog = (level, message, additionalInfo) => {
        if (!additionalInfo) {
            additionalInfo = {}
        }
        additionalInfo.app = applicationName;
        additionalInfo.endpoint = endpointName;
        additionalInfo.env = environment;

        let appLog = {
            date: parseInt(moment().format("x")),
            level: level,
            message: message,
            additionalInfo: additionalInfo
        };
        esExecutePost('/endpoints/logs', appLog)
            .then(body => logDebug('[APP LOG][' + level + '] ' + appLog.message))
            .catch(error => {
                logDebug('[APP LOG][' + level + '] ' + appLog.message + ' >> [NO SENT]');
                logInfo('Error when try to send app log to ES [' + error + ']')
            })
    };
    const appLogDebug = (message, additionalInfo) => sendAppLog('DEBUG', message, additionalInfo);
    const appLogInfo = (message, additionalInfo) => sendAppLog('INFO', message, additionalInfo);
    const appLogWarn = (message, additionalInfo) => sendAppLog('WARN', message, additionalInfo);
    const appLogError = (message, additionalInfo) => sendAppLog('ERROR', message, additionalInfo);

    let lastStatistic = null;

    // events (POST /api/endpoints/events)
    const sendEvent = (eventName, data, type) => {
        if (!eventName) {
            throw 'Event name is empty'
        }
        if (!data) {
            data = {}
        }
        let eventBody = {
            date: parseInt(moment().format("x")),
            event: eventName,
            data: data
            // TODO callback fields: fromFunction
            // TODO per user fields: userId, userEmail
        };
        esExecutePost('/endpoints/events', eventBody)
            .then(body => logDebug('[EVENT][' + eventName + '][type: ' + (data.type || type || '-') + '] >> [SENT]'))
            .catch(error => {
                logDebug('[EVENT][' + eventName + '][type: ' + (data.type || type || '-') + '] >> [NO SENT]');
                logInfo('Error when try to send event to ES [' + error + ']')
            });

        if(!lastStatistic || moment().subtract(1, 'hour').isAfter(lastStatistic)) {
            lastStatistic = moment();
            logInfo(">>> mem usage: " + util.inspect(process.memoryUsage(), {showHidden: true, depth: null}));
        }
    };

    // TODO implements ES get file from app	(GET /api/endpoints/files/{fileId})
    // TODO implements ES save file on app (POST /api/endpoints/files)

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Watson (Tone Analyzer) functionality
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    /////////////////////
    // configuration clients
    /////////////////////
    const parseHttpUrl = (request) => {
        if(request && request.path && request.path.startsWith("http")){
            return request.path;
        }
        let path = request && request.path ? request.path : 'v3/tone';
        path = path.startsWith("/") ? path : '/'+path;
        return 'https://'+username+':'+password+'@gateway.watsonplatform.net/tone-analyzer/api'+path;
    };

    const parseHttpQuery = (request) => {
        let query = {};
        if(request && request.params){
            query = request.params;
        }
        if(!query.version){
            query.version = '2016-05-19';
        }
        return query
    };

    const parseHttpHeaders = (request) => {
        let headers = {};
        if(request && request.headers){
            headers = request.headers;
        }
        if(!headers['Content-Type']){
            headers['Content-Type'] = 'application/json';
        }
        return headers
    };

    const httpGet = (req, cb) => {
        let options = {
            method: 'GET',
            url: parseHttpUrl(req),
            qs: parseHttpQuery(req),
            headers: parseHttpHeaders(req),
            json: true,
            accept: '*/*'
        };
        request.get(options, (err, resp, body) => {
            if(cb) {
                if (err) {
                    logError("ERROR: " + JSON.stringify(err));
                    cb(err, null)
                }
                cb(null, body)
            }
        });
    };
    const syncHttpGet = deAsync(httpGet);

    const httpPost = (req, cb) => {
        let options = {
            method: 'POST',
            url: parseHttpUrl(req),
            qs: parseHttpQuery(req),
            headers: parseHttpHeaders(req),
            json: true,
            accept: '*/*',
            body: req && req.body ? req.body : {}
        };
        request.post(options, (err, resp, body) => {
            if(cb) {
                if (err) {
                    logError("ERROR: " + JSON.stringify(err));
                    cb(err, null)
                }
                cb(null, body)
            }
        });
    };
    const syncHttpPost = deAsync(httpPost);

    /////////////////////
    // functions
    /////////////////////

    const genericHttpGet = params => {
        return syncHttpGet(params);
    };
    const genericHttpPost = params => {
        return syncHttpPost(params);
    };

    const genericHttpFunctions = {
        get: genericHttpGet,    // Sends a GET request
        post: genericHttpPost	// Sends a POST request
    };

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // HTTP service: Webhook
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    // Webhooks are not used at this moment

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // HTTP service: Endpoint API
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    appLogInfo('Endpoint ['+endpointName+'] is being initialized');

    const apiRouter = express.Router();

    let firstLocalDeploymentWarning = false;

    // Health check
    apiRouter.get('/system/alive', (req, res) => {
        let validToken = false;
        if (req.headers && req.headers.token && token === req.headers.token) {
            validToken = true
        }
        if(!validToken && localDeployment){
            // if the endpoint is running in local environment, pass token validation
            if(!firstLocalDeploymentWarning) {
                firstLocalDeploymentWarning = true;
                logWarn("Invalid or empty token on request. Ignored exceptions of this kind because the endpoint is running in local deployment.");
            }
            validToken = true
        }
        if (validToken) {
            res.send({started: true});
        } else {
            logInfo("Invalid token when try to check health");
            res.status(401).send('Invalid token')
        }
    });

    // Termination
    apiRouter.get('/system/terminate', (req, res) => {
        let validToken = false;
        if (req.headers && req.headers.token && token === req.headers.token) {
            validToken = true
        }
        if(!validToken && localDeployment){
            // if the endpoint is running in local environment, pass token validation
            if(!firstLocalDeploymentWarning) {
                firstLocalDeploymentWarning = true;
                logWarn("Invalid or empty token on request. Ignored exceptions of this kind because the endpoint is running in local deployment.");
            }
            validToken = true
        }
        if (validToken) {
            logInfo('Stopping endpoint [' + endpointName + ']...');
            res.send('ok');
            process.exit(0)
        } else {
            logInfo("Invalid token when try to terminate process");
            res.status(401).send('Invalid token')
        }
    });

    // process functions
    apiRouter.post('/function', (req, res) => {
        let validToken = false;
        if (req.headers && req.headers.token && token === req.headers.token) {
            validToken = true
        }
        if(!validToken && localDeployment){
            // if the endpoint is running in local environment, pass token validation
            if(!firstLocalDeploymentWarning) {
                firstLocalDeploymentWarning = true;
                logWarn("Invalid or empty token on request. Ignored exceptions of this kind because the endpoint is running in local deployment.");
            }
            validToken = true
        }
        let response = null;
        let responseCode = 200;
        if (validToken) {
            try {
                let functionName = req.body.function;
                if (!functionName) {
                    response = convertException('Empty function name', {code: 'argumentException', name: 'Argument invalid'});
                    responseCode = 404;
                } else {
                    let fcName = genericHttpFunctions[functionName];
                    if (fcName) {
                        // generic HTTP function
                        logDebug('[FUNCTION][' + functionName + '] executing function request');
                        response = fcName(req.body ? (req.body.params || {}) : {})
                    } else {
                        // invalid function
                        response = convertException('Function [' + functionName + '] is not defined for the endpoint', {code: 'argumentException', name: 'Argument invalid'});
                        responseCode = 404;
                    }
                }
            } catch (err) {
                response = convertException(util.inspect(err, { showHidden: true, depth: null }));
                responseCode = 500;
            }
            if (!response) {
                response = convertException("Empty endpoint response");
                responseCode = 400;
            }
            res.status(responseCode).send({
                date: parseInt(moment().format("x")),
                data: response
            })
        } else {
            logInfo("Invalid token when try to execute function request");
            res.status(401).send('Invalid token')
        }
    });

    // get configuration
    apiRouter.get('/configuration', (req, res) => {
        logInfo("Configuration request");
        let validToken = false;
        if (req.headers && req.headers.token && token === req.headers.token) {
            validToken = true
        }
        if(!validToken && localDeployment){
            // if the endpoint is running in local environment, pass token validation
            if(!firstLocalDeploymentWarning) {
                firstLocalDeploymentWarning = true;
                logWarn("Invalid or empty token on request. Ignored exceptions of this kind because the endpoint is running in local deployment.");
            }
            validToken = true
        }
        let response = null;
        if (validToken) {
            try {
                let json = JSON.parse(fs.readFileSync('./endpoint.json', 'utf8'));
                if (json) {
                    response = {
                        app: applicationName,
                        name: endpointName,
                        env: environment,
                        perUser: false,
                        configuration: {
                            _endpoint_name: endpointName,
                            _app_name: applicationName,
                            _pod_id: podId,
                            _environment: environment,
                            _local_deployment: localDeployment,
                            _custom_domain: domainCustom,
                            _base_domain: domainBase,
                            _webservices_port: webServicesPort,
                            _debug: debug,
                            _token: '-',
                            _profile: profile,
                            _endpoints_services_api: endpointsServicesApi,
                            _endpoint_config: {
                                username: username,
                                password: password
                            }
                        },
                        js: '',
                        listeners: '',
                        functions: [],
                        events: []
                    };

                    if(!!json.configurationHelpUrl){
                        response.configurationHelpUrl = json.configurationHelpUrl;
                    }
                    if(!!json.functions){
                        response.functions = json.functions;
                    }
                    if(!!json.events){
                        response.events = json.events;
                    }
                    if(!!json.configuration){
                        response.conf = json.configuration;
                    }
                    if(!!json.userConfiguration){
                        response.userConf = json.userConfiguration;
                    }
                    if(!!json.userConfigurationButtons){
                        response.userConfButtons = json.userConfigurationButtons;
                    }
                    if(!!json.scripts){
                        let scripts = '';
                        for(let i in json.scripts){
                            let fileContent = fs.readFileSync('./scripts/'+json.scripts[i], 'utf8');
                            if(fileContent){
                                try {
                                    scripts += '\n/* */\n';
                                    scripts += fileContent;
                                    scripts += '\n/* */\n';
                                } catch (err){
                                    logWarn('JS file ['+json.scripts[i]+'] can not be read: '+convertException(err));
                                }
                            }
                        }
                        response.js = scripts;
                    }
                    if(!!json.listeners){
                        let listeners = '';
                        for(let i in json.listeners){
                            let fileContent = fs.readFileSync('./listeners/'+json.listeners[i], 'utf8');
                            if(fileContent){
                                try {
                                    listeners += '\n/* */\n';
                                    listeners += fileContent;
                                    listeners += '\n/* */\n';
                                } catch (err){
                                    logWarn('Listeners file ['+json.listeners[i]+'] can not be read: '+convertException(err));
                                }
                            }
                        }
                        response.listeners = listeners;
                    }
                } else {
                    logInfo("Empty metadata file when try to execute configuration request");
                    response = convertException('Empty metadata file')
                }
            } catch (err) {
                if(err && err.message) {
                    response = convertException(err.message)
                } else {
                    err = util.inspect(err, {showHidden: true, depth: null});
                    if(err && err.startsWith("'") && err.endsWith("'")){
                        err = err.substring(1, err.length - 1);
                    }
                    response = convertException(err)
                }
            }
            if (!response) {
                response = convertException("Empty endpoint response")
            }
            logInfo("Configuration response from endpoint");
            res.send(response)
        } else {
            logInfo("Invalid token when try to get configuration");
            res.status(401).send('Invalid token')
        }
    });

    const webServicesServer = express();
    webServicesServer.use(compression());
    webServicesServer.use(bodyParser.urlencoded({extended: true})); // configure app to use bodyParser()
    webServicesServer.use(bodyParser.json()); // this will let us get the data from a POST
    webServicesServer.use('/api', apiRouter); // all of our routes will be prefixed with /api
    if (useSsl) {
        // start https service
        const sslCredentials = {
            key: sslKey,
            cert: sslCert
        };
        https.createServer(sslCredentials, webServicesServer).listen(webServicesPort, function () {
            logInfo('Https service ready on port [' + webServicesPort + ']');
        });
    } else {
        // start http service
        http.createServer(webServicesServer).listen(webServicesPort, function () {
            logInfo('Http service ready on port [' + webServicesPort + ']');
        });
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////////
    // Endpoint Started
    ///////////////////////////////////////////////////////////////////////////////////////////////////

    logInfo(">>> mem init usage: "+util.inspect(process.memoryUsage(), { showHidden: true, depth: null }));
    appLogInfo('Endpoint ['+endpointName+'] started');

    module.exports = webServicesServer;
})(require, process, module);
