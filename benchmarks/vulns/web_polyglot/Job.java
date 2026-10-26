import java.io.*;

public class Job {
  void run(String userCmd, ObjectInputStream in) throws Exception {
    Runtime.getRuntime().exec(userCmd);
    Object o = in.readObject();
  }
}
