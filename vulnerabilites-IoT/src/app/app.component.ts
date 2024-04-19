import { NgModule } from '@angular/core';
import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { MatIconModule, MatIconRegistry } from '@angular/material/icon';
import { NgClass } from '@angular/common';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [RouterOutlet,MatIconModule,NgClass],
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'vulnerabilites-IoT';

  filterdivActive = false;

  toggleFilterDiv() {
    this.filterdivActive = !this.filterdivActive;
  }

}
