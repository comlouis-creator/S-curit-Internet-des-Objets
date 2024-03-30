import { NgModule } from '@angular/core';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { AppComponent } from './app.component';

@NgModule({
  imports: [
    MatIconModule
  ],
  providers: [
    MatIconRegistry
  ],
  bootstrap: []
})
export class AppModule { }