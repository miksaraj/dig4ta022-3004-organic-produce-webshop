<template>
	<div>
		<b-jumbotron fluid header="Kappaleen otsikko" lead="Alaotsikko">
			<template v-slot:lead>
				Tämän kappaleen tehtäviin pääset klikkaamalla tästä:
			</template>
			<b-button class="btn-primary">Tehtävät</b-button>
		</b-jumbotron>
		<b-container fluid>
			<component
				v-for="item in items"
				:key="item.order"
				:is="item.type"
			/>
		</b-container>
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
const Assignment = () => import('~/components/Assignment.vue')
const MultipleChoice = () => import('~/components/MultipleChoice.vue')
const SpecialText = () => import('~/components/SpecialText.vue')
const TheoryElement = () => import('~/components/TheoryElement.vue')
export default {
	components: {
		Assignment,
		MultipleChoice,
		SpecialText,
		TheoryElement
	},
	computed: {
		...mapGetters('structure', ['sectionStructure']),
		items() {
			return this.sectionStructure(1)
		}
	}
}
</script>
