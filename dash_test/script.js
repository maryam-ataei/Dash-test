var data=[];
var t_fps='60';
var t_resolution='1920X1080';
var t_bitrate='40000';
var t_bufferLevel='10';
var saveBtn=document.getElementById("save_btn");

function saveDate(filename, text){
    var pom = document.createElement('a');
    pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    pom.setAttribute('download', filename);
    if (document.createEvent) {
        var event = document.createEvent('MouseEvents');
        event.initEvent('click', true, true);
        pom.dispatchEvent(event);
    } else {
        pom.click();
    }
}

saveBtn.onclick=function(){
	var t_data=data.join('')
    var dataString=t_data.toString();
    //Maryam_start: new changes
    var now = new Date();
    var timestamp =
        now.getFullYear() + '-' +
        String(now.getMonth() + 1).padStart(2, '0') + '-' +
        String(now.getDate()).padStart(2, '0') + '_' +
        String(now.getHours()).padStart(2, '0') + '-' +
        String(now.getMinutes()).padStart(2, '0') + '-' +
        String(now.getSeconds()).padStart(2, '0');

    var filename = "Tester_" + timestamp + ".txt";
    ///////////////////////////////Maryam_end
    
    saveDate(filename, dataString);
    // saveBtn.style.display="none";
    //startBtn.style.display="block";s
}

var timer=setTimeout(function(){
	saveBtn.click();
},10000)

<!--setup the video element and attach it to the Dash player-->
    function display(){
        var datetime = new Date();
        console.log(datetime)
        var url = "http://130.215.28.249/manifest.mpd?t="+datetime;
        var player = dashjs.MediaPlayer().create();
        player.updateSettings({
		  streaming: {
		    buffer:{
		    	bufferToKeep: 20,
		    	stableBufferTime: 20,
    			bufferTimeAtTopQuality: 40,
    			fastSwitchEnabled: true,
    			initialBufferLevel: NaN
		    }
		  }
        });
        
        player.initialize(document.querySelector("#video"), url, true);
        player.on(dashjs.MediaPlayer.events["PLAYBACK_ENDED"], function () {
    clearInterval(eventPoller);
    clearInterval(bitrateCalculator);
    // Maryam_start: new changes
    saveBtn.click();
    //////////////////// Maryam_end
});

var eventPoller = setInterval(function () {
    var streamInfo = player.getActiveStream().getStreamInfo();
    var dashMetrics = player.getDashMetrics();
    var dashAdapter = player.getDashAdapter();

    if (dashMetrics && streamInfo) {
        const periodIdx = streamInfo.index;
        var repSwitch = dashMetrics.getCurrentRepresentationSwitch('video', true);
        var bufferLevel = dashMetrics.getCurrentBufferLevel('video', true);
        var bitrate = repSwitch ? Math.round(dashAdapter.getBandwidthForRepresentation(repSwitch.to, periodIdx) / 1000) : NaN;
        var adaptation = dashAdapter.getAdaptationForType(periodIdx, 'video', streamInfo);
        var currentRep = adaptation.Representation_asArray.find(function (rep) {
            return rep.id === repSwitch.to
        })
        var frameRate = currentRep.frameRate;
        var resolution = currentRep.width + 'x' + currentRep.height;
        var cur_biterate = player.getAverageThroughput('video', true);

        var t_time=document.getElementById('video').currentTime;



        t_fps=frameRate;
        t_resolution=resolution;
        t_bitrate=bitrate;
        t_bufferLevel=bufferLevel;

        temp_data=t_time+':'+t_fps+','+t_resolution+','+t_bitrate+','+t_bufferLevel+'\n';
        data.push(temp_data);


        document.getElementById('bufferLevel').innerText = bufferLevel + " secs";
        document.getElementById('framerate').innerText = frameRate + " fps";
        document.getElementById('reportedBitrate').innerText = bitrate + " Kbps";
        document.getElementById('resolution').innerText = resolution;
        // document.getElementById('calculatedBitrate').innerText = Math.round(cur_biterate);
    }
}, 1000);

if (video.webkitVideoDecodedByteCount !== undefined) {
    var lastDecodedByteCount = 0;
    const bitrateInterval = 5;
    var bitrateCalculator = setInterval(function () {
        var calculatedBitrate = (((video.webkitVideoDecodedByteCount - lastDecodedByteCount) / 1000) * 8) / bitrateInterval;
        document.getElementById('calculatedBitrate').innerText = Math.round(calculatedBitrate) + " Kbps";
        lastDecodedByteCount = video.webkitVideoDecodedByteCount;
    }, bitrateInterval * 1000);
} else {
    document.getElementById('chrome-only').style.display = "none";
}

    };
