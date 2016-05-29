<?
	$msg=$_POST['test_msg'];
	$dataArray=array();
	$cols=array();
	$rows=array();
	$c=array();

	$cols[0]['id']=""; $cols[0]["label"]="Country"; $cols[0]["pattern"]=""; $cols[0]["type"]="string";
	$cols[1]['id']=""; $cols[1]["label"]="Traffic"; $cols[1]["pattern"]=""; $cols[1]["type"]="number";

	$c[0]['v']="RU"; $c[0]['f']="";
	$c[1]['v']=2324; $c[1]['f']="";

	$rows[0]['c']=$c;

	$c[0]['v']="CA"; $c[0]['f']="";
	$c[1]['v']=6453; $c[1]['f']="";

	$rows[1]['c']=$c;

	$c[0]['v']="US"; $c[0]['f']="";
	$c[1]['v']=531; $c[1]['f']="";

	$rows[2]['c']=$c;


	$dataArray[0]=$cols;
	$dataArray[1]=$rows;

	if($msg==1)
	{
		echo json_encode($dataArray);
	}
?>