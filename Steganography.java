 
import javax.swing.JOptionPane;
import java.io.File;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.awt.image.WritableRaster;
import java.awt.image.DataBufferByte;
import javax.imageio.ImageIO;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author vignesh
 */
public class Steganography
{
	
    public Steganography(){}
	
	
    public boolean encode(String path, String cover, String ext, String stegan, String message){
	String	file_name = image_path(path,cover,ext);
	BufferedImage image_cover = getImage(file_name);
	BufferedImage image = user_space(image_cover);
	image = add_text(image,message);
		
	return(setImage(image,new File(image_path(path,stegan,"png")),"png"));
    }
	
	
    public String decode(String path, String name){
	byte[] decode;
	try{
            BufferedImage image  = user_space(getImage(image_path(path,name,"png")));
            decode = decode_text(get_byte_data(image));
            return(new String(decode));
	}
	catch(Exception e){
            JOptionPane.showMessageDialog(null, "There is no hidden message in this image!","Error",JOptionPane.ERROR_MESSAGE);
            return "";
	}
    }
	
    
    private String image_path(String path, String name, String ext){
	return path + "/" + name + "." + ext;
    }

    
    //get method to return an image file
    private BufferedImage getImage(String fname){
	BufferedImage image = null;
	File file = new File(fname);	
	try{
            image = ImageIO.read(file);
	}
	catch(Exception ex){
            JOptionPane.showMessageDialog(null, "Unable to read image","Error",JOptionPane.ERROR_MESSAGE);
	}
	return image;
    }
	
	
    //Set method to save an image file
    private boolean setImage(BufferedImage image, File file, String ext){
	try{
            file.delete(); //delete resources used by the File
            ImageIO.write(image,ext,file);
            return true;
	}
	catch(Exception e){
            JOptionPane.showMessageDialog(null, "Unable to save file","Error",JOptionPane.ERROR_MESSAGE);
            return false;
	}
    }
	
	
    //Handles the addition of text into an image
    private BufferedImage add_text(BufferedImage image, String text){
	//convert all items to byte arrays: image, message, message length
	byte img[]  = get_byte_data(image);
	byte msg[] = text.getBytes();
	byte len[]   = bit_conversion(msg.length);
	try{
            encode_text(img, len,  0); 
            encode_text(img, msg, 32); 
	}
	catch(Exception e){
            JOptionPane.showMessageDialog(null, "Target File cannot hold message!", "Error",JOptionPane.ERROR_MESSAGE);
	}
	return image;
    }
	
	
    //Creates a user space version of a Buffered Image for editing and saving bytes
    private BufferedImage user_space(BufferedImage image){
	BufferedImage new_img  = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_3BYTE_BGR);
	Graphics2D graphics = new_img.createGraphics();
	graphics.drawRenderedImage(image, null);
	graphics.dispose(); 
	return new_img;
    }
	
    
    private byte[] get_byte_data(BufferedImage image){
	WritableRaster raster   = image.getRaster();
	DataBufferByte buffer = (DataBufferByte)raster.getDataBuffer();
	return buffer.getData();
    }
	
	
    //Gernerates byte format of an integer
    private byte[] bit_conversion(int i){ 
	byte byte0 = (byte)((i & 0x000000FF)	   );
	return(new byte[]{0,0,0,byte0});
    }
	
    
    //Encode an array of bytes into another array of bytes at a supplied offset
    private byte[] encode_text(byte[] image, byte[] addition, int offset){
	if(addition.length + offset > image.length){
            throw new IllegalArgumentException("File not long enough!");
	}
	for(int i=0; i<addition.length; ++i){
            int add = addition[i];
            for(int bit=7; bit>=0; --bit, ++offset){
                int b = (add >>> bit) & 1;
		image[offset] = (byte)((image[offset] & 0xFE) | b );
            }
	}
	return image;
    }
	
	
    //Retrieves hidden text from an image
    private byte[] decode_text(byte[] image){
	int length = 0;
	int offset  = 32;
	for(int i=0; i<32; ++i){
            length = (length << 1) | (image[i] & 1);
	}
	byte[] result = new byte[length];
	for(int b=0; b<result.length; ++b ){
            for(int i=0; i<8; ++i, ++offset){		
		result[b] = (byte)((result[b] << 1) | (image[offset] & 1));
            }
	}
	return result;
    }
}


