package de.unitrier.infsec.environment;

class NodeValue {
	int value;
	NodeValue next;
	NodeValue(int v, NodeValue n) {
		value = v; next = n;
	}
}

class NodeList {
	public class Node {
		public String entry;
		public Node next;

		public Node(String entry) {
			this.entry = entry;
			this.next=null;
		}
	}

	public Node head, last;
	public void add(String entry) {
		Node newEntry=new Node(entry);
		if(head==null)
			head=last=newEntry;
		else {
			last.next=newEntry;
			last=newEntry;
		}
	}
}

public class Environment {

	private static boolean result; // the LOW variable
	
	private static NodeValue listValue = null;
	private static boolean listInitializedValue = false;
	private static NodeValue initialValue() {
		// Unknown specification of the following form:
		// return new Node(U1, new Node(U2, ...));
		// where U1, U2, ...Un are constant integers.
		return new NodeValue(1, new NodeValue(7,null));  // just an example
	}
	
	public static int untrustedInput() {
    	if (!listInitializedValue) {
    		listValue = initialValue();
    	    listInitializedValue = true;        
    	}
    	if (listValue==null) return 0;
    	int tmp = listValue.value;
    	listValue = listValue.next;
    	return tmp;
	}
		
    public static void untrustedOutput(int x) {
		if (untrustedInput()!=0) {
			result = (x==untrustedInput());
			throw new Error();  // abort
		}
	}
	
    public static byte[] untrustedInputMessage() {
		int len = untrustedInput();
		if (len<0) return null;
		byte[] returnval = new byte[len];
		for (int i = 0; i < len; i++)
			returnval[i] = (byte) untrustedInput();
		return returnval;    
    }
    
    public static void untrustedOutputMessage(byte[] t) {
    	untrustedOutput(t.length);
		for (int i = 0; i < t.length; i++) {
			untrustedOutput(t[i]);
		}
    }
    
	private static NodeList stringsList = null;

	public static String untrustedInputString() {
		int choice = untrustedInput();
		if(choice==1){ // return a new string
    		int l=untrustedInput();
    		String s="";
    		for(int i=0; i<l; i++)
    			s += (char) untrustedInput();
    		if(stringsList==null)
    			stringsList = new NodeList();
    		stringsList.add(s);
    		return s;
		} else if (choice==2){ // return a string previously exchanged
    		if(stringsList==null)
    			return "";
    		for(NodeList.Node node=stringsList.head; node!=null; node=node.next)	
    			if(untrustedInput()!=0)
    				return node.entry;
    	}
		return "";
    }
    
    public static void untrustedOutputString(String s) {
    	if(stringsList==null)
    		stringsList = new NodeList();
    	// value comparison
    	untrustedOutput(s.length());
    	for (int i = 0; i < s.length(); i++)
        	untrustedOutput(s.charAt(i));
    	// reference comparison
    	for(NodeList.Node node=stringsList.head; node!=null; node=node.next)
    		untrustedOutput(s==node.entry ? 1:0);
    	stringsList.add(s);
    }
}
