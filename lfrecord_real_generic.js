
// author: Shafqat Rehman (shafqat.rehman@gmail.com)


#!/usr/bin/env nodejs
var fs = require("fs");
var http = require('http');

// var keys = 'inputifindex,ethernetprotocol,macsource,macdestination,ipprotocol,ipsource,ipdestination';
var keys = 'ipprotocol,ipsource,ipdestination';
var value = 'bytes';
var filter = 'direction=ingress';
var thresholdValue = 800000/8;
var metricName = 'mark';
var tos = '0x80';

var elephants = {};
var uindex = 0;		// for udp
var tindex = 0; 	// for tcp

// mininet mapping between sFlow ifIndex numbers and switch/port names
var ifindexToPort = {};
var nameToPort = {};
/*var path = '/sys/devices/virtual/net/';
var devs = fs.readdirSync(path);
for(var i = 0; i < devs.length; i++) {
  var dev = devs[i];
  var parts = dev.match(/(.*)-(.*)/);
  if(!parts) continue;

  var ifindex = fs.readFileSync(path + dev + '/ifindex');
  var port = {"switch":parts[1],"port":dev};
  console.log("ifindex: " + ifindex + " port: " + JSON.stringify(port));
  ifindexToPort[parseInt(ifindex).toString()] = port;
  nameToPort[dev] = port;
}*/

var fl = { hostname: 'localhost', port: 8080 };


var groups = {'external':['0.0.0.0/0'],'internal':['10.0.0.2/32']};
var rt = { hostname: 'localhost', port: 8008 };
var flows = {'keys':keys,'value':value,'filter':filter};
var threshold = {'metric':metricName,'value':thresholdValue,'byFlow':true,'timeout':5};

function extend(destination, source) {
  for (var property in source) {
    if (source.hasOwnProperty(property)) {
      destination[property] = source[property];
    }
  }
  return destination;
}

function jsonGet(target,path,callback) {
  var options = extend({method:'GET',path:path},target);
  console.log("options: " + JSON.stringify(options));
  var req = http.request(options,function(resp) {
    var chunks = [];
    resp.on('data', function(chunk) { chunks.push(chunk); });
    resp.on('end', function() { callback(JSON.parse(chunks.join(''))); });
  });
  req.end();
};

function jsonPut(target,path,value,callback) {
  var options = extend({method:'PUT',headers:{'content-type':'application/json'}
,path:path},target);
  var req = http.request(options,function(resp) {
    var chunks = [];
    resp.on('data', function(chunk) { chunks.push(chunk); });
    resp.on('end', function() { callback(chunks.join('')); });
  });
  req.write(JSON.stringify(value));
  req.end();
};


function jsonPost(target,path,value,callback) {
  var options = extend({method:'POST',headers:{'content-type':'application/json'},"path":path},target);
  var req = http.request(options,function(resp) {
    var chunks = [];
    resp.on('data', function(chunk) { chunks.push(chunk); });
    resp.on('end', function() { callback(chunks.join('')); });
  });
  req.write(JSON.stringify(value));
  req.end();
}

function lookupOpenFlowPort(agent,ifIndex) {
  console.log("ifindex : " + ifIndex);
  return ifindexToPort[ifIndex];
}

function record(agent,dataSource,flowkey) {
  var parts = flowkey.split(',');
  // var port = lookupOpenFlowPort(agent,dataSource);
  // if(!port || !port.dpid) return;
  var src_dst = parts.toString();  // get comma separated string 
  var lf = elephants[src_dst];
  if (!lf) {
     if (parts[0] == 0x11)
        lf = "udp_lf" + uindex++; 	// It is a udp flow
     else if (parts[0] == 0x06) 
        lf = "tcp_lf" + tindex++;	// It is a tcp flow
      else {
        lf = "lf" + Object.keys(elephants).length;
      }
  }
  else return;	// this flow definition already exists				
  console.log("recording flow key:" + JSON.stringify(flowkey) + " lf name: " + lf);
  elephants[src_dst] = lf;
  // Push the definition of this large flow to sflow-rt
  var lf_filter = "";
  var key_names = keys.split(',');
  lf_filter += key_names[0] + '=';
  lf_filter += parts[0];
  for (var i = 1; i < parts.length; i++){
    lf_filter += '&';
    lf_filter += key_names[i] + '=';
    lf_filter += parts[i];
  }
  var elephant = {'keys':keys, 'value':value, 'filter':lf_filter, "t":'1' };
  console.log("elephant=" + JSON.stringify(elephant)); 
  jsonPut(rt, '/flow/'+lf+'/json',elephant, function() {}
         );
}


function mark(agent,dataSource,flowkey) {
  var parts = flowkey.split(',');
  var port = lookupOpenFlowPort(agent,dataSource);
  if(!port || !port.dpid) return;

  var message = {"switch":port.dpid,
                 "name":"elephant-1",
                 "cookie":"0",
                 "ether-type":parts[1],
                 "protocol":parts[4],
                 "src-ip":parts[5],
                 "dst-ip":parts[6],
                 "priority":"500",
                 "active":"true",
                  "actions":"set-tos-bits="+tos+",output=normal"};
  console.log("message=" + JSON.stringify(message));
  jsonPost(fl,'/wm/staticflowentrypusher/json',message,
      function(response) {
         console.log("result=" + JSON.stringify(response));
      });

}

function blockFlow(agent,dataSource,topKey) {
  var parts = topKey.split(',');
  console.log("top key: " + parts);
  // var port = lookupOpenFlowPort(agent,parts[0]);
  var port = lookupOpenFlowPort(agent,dataSource);
  console.log("port : " + JSON.stringify(port));
  if(!port || !port.dpid) return;
  console.log("blocking flow ... "); 
  var message = {"switch":port.dpid,
                 "name":"dos-1",
                 "ingress-port":port.portNumber.toString,
                 "ether-type":parts[1],
                 "protocol":parts[4],
                 "src-ip":parts[5],
                 "dst-ip":parts[6],
                 "priority":"32767",
                 "active":"true"};

  console.log("message=" + JSON.stringify(message));
  jsonPost(fl,'/wm/staticflowentrypusher/json',message,
      function(response) {
         console.log("result=" + JSON.stringify(response));
         // Block this flow
         blockFlow(agent,dataSource,topKey);
      });
}

function getTopFlows(event) {
  jsonGet(rt,'/metric/' + event.agent + '/' + event.dataSource + '.' + event.metric + '/json',
    function(metrics) {
      console.log("metrics: " + JSON.stringify(metrics));
      if(metrics && metrics.length == 1) {
        var metric = metrics[0];
        // console.log("metric: " + JSON.stringify(metric));
        console.log("metric value = " + metric.metricValue + " threshold = " + thresholdValue);
        if(metric.metricValue > thresholdValue
           && metric.topKeys
           && metric.topKeys.length > 0) {
            var topKey = metric.topKeys[0].key;
            console.log("top key: " + topKey);
            //blockFlow(event.agent,event.dataSource,topKey);
            //mark(event.agent,event.dataSource,topKey);
            record(event.agent,event.dataSource,topKey);
        }
      }
    }
  );  
}

function getEvents(id) {
  jsonGet(rt,'/events/json?maxEvents=10&timeout=60&eventID='+ id,
    function(events) {
      var nextID = id;
      if(events.length > 0) {
        nextID = events[0].eventID;
        events.reverse();
        for(var i = 0; i < events.length; i++) {
          if(metricName == events[i].thresholdID) getTopFlows(events[i]);
        }
      }
      getEvents(nextID);  
    }
  );
}

// use port names to link dpid and port numbers from Floodlight
function getSwitches() {
  jsonGet(fl,'/wm/core/controller/switches/json',
    function(switches) { 
      for(var i = 0; i < switches.length; i++) {
        var sw = switches[i];
        var ports = sw.ports;
        for(var j = 0; j < ports.length; j++) {
          var port = nameToPort[ports[j].name];
          if(port) {
            port.dpid = sw.dpid;
            port.portNumber = ports[j].portNumber;
          }
        }
      }
      setGroup();
    }
  );
}

function setGroup() {
  jsonPut(rt,'/group/json',
    groups,
    function() { setFlows(); }
  );
}

function setFlows() {
  jsonPut(rt,'/flow/' + metricName + '/json',
    flows,
    function() { setThreshold(); }
  );

  // Define mouse and elephant flow
  /*jsonPut(rt, '/flow/tos0/json',{"value":'bytes',"filter":'iptos=00000000',"t":'1'}, 
         function() {}
  );
  jsonPut(rt, '/flow/tos128/json',{"value":'bytes',"filter":'iptos=10000000',"t":'1'},
         function(){}
  );*/
}

function setThreshold() {
  jsonPut(rt,'/threshold/' + metricName + '/json',
    threshold,
    function() { getEvents(-1); }
  ); 
}

function initialize() {
  // getSwitches();
  setGroup();
}

// initialize();

if (require.main == module){
  // Get the threshold from the command line
  var thld = '', tv = thresholdValue; // default is 100 KBps
  process.argv.forEach(function(val, index, array){
    // console.log(index + ": " + val);
    if (index == 2 && val == '--help') {
      console.log("Commandline Syntax :");
      console.log("                   " + array[1] + " --thld  bitrate\r\n");
      console.log("                   Where bitrate must be specified as bps i.e., bits per second.");
      console.log("                   Default threshold bitrate is 800 Kbps.");
      process.exit();
    };
    if (index == 2 && val == '--thld') thld = val;
    if (index == 3 && val > tv ) tv = val/8; 
  });
  // Set the threshold
  if (thld == '--thld' && tv )  thresholdValue = tv;
  console.log("Elephant Flow Threshold : " + thresholdValue/1000000 + " MBps");

  initialize();
}

