package com.hellocmu.picoctf;
public class MainActivity extends androidx.appcompat.app.AppCompatActivity {
    android.widget.Button button;
    android.content.Context ctx;
    android.widget.TextView text_bottom;
    android.widget.EditText text_input;
    android.widget.TextView text_top;

    public MainActivity()
    {
        return;
    }

    public void buttonClick(android.view.View p4)
    {
        this.text_bottom.setText(com.hellocmu.picoctf.FlagstaffHill.getFlag(this.text_input.getText().toString(), this.ctx));
        return;
    }

    protected void onCreate(android.os.Bundle p3)
    {
        super.onCreate(p3);
        this.setContentView(2131296284);
        this.text_top = ((android.widget.TextView) this.findViewById(2131165322));
        this.text_bottom = ((android.widget.TextView) this.findViewById(2131165320));
        this.text_input = ((android.widget.EditText) this.findViewById(2131165321));
        this.ctx = this.getApplicationContext();
        System.loadLibrary("hellojni");
        this.text_top.setText(2131427368);
        return;
    }
}
