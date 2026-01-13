import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Reader {
    public static void main(String[] args) {
        try {
            List<String> addresses = new ArrayList<>();
            for (int i = 1; i < 4000; i+=100) {
                File f = new File("wallet list " + i + "-" + (i+99) + ".txt");
                System.out.println(f.getAbsolutePath());
                Scanner scan = new Scanner(f);
                while (scan.hasNextLine()) {
                    String line = scan.nextLine();
                    line = line.trim();
                    line = line.replaceAll("\"", "");
                    line = line.replaceAll(",", "");
                    if (line.length() < 10) {
                        continue;
                    }
                    addresses.add(line.trim());
                }
            }

            PrintWriter out = new PrintWriter(new File("walletlist.txt"));
            System.out.println("Addresses: " + addresses.size());
            for (int i = 0; i < addresses.size(); i++) {
                out.println(addresses.get(i));
            }
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
