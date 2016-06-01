<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.5.1/jquery.min.js"></script>
<script>
	$.post("back.php", { test_msg: 1 },
		function(data)
		{
			alert("Data Loaded: " + data);
		}
   );
</script>